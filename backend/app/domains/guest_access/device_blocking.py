"""Making a ``BLOCKLIST`` *device* rule true on the venue's MikroTik routers.

## What was wrong

A device rule (``DeviceAccessRule``: block this MAC) was a login-gate check
and nothing else. ``GuestAccessService.check_access`` refused the MAC at its
next sign-in, and the router agent's ``/agent/authorized-macs`` stopped
listing it. Nothing told the router. So:

* a device already online stayed online until its session ended on its own;
* a device the venue had bypassed (a trusted device, a hand-made binding)
  never signs in, so the gate was never asked;
* the "Block device" button on a connected device reported success over a
  router that kept forwarding for it.

## What this does

For every MikroTik router in the rule's scope -- the rule's own location, or
every router of the organization for an organization-wide rule -- one
connection over 8728 (``MikroTikGuestAccessAdapter.block_device``):

1. ``/ip hotspot ip-binding add mac-address=<mac> type=blocked
   comment=cloudguest-devblock:<rule id>``, idempotent on the comment,
   placed ahead of every other binding, read back;
2. the device's ``/ip hotspot active`` and ``/ip hotspot host`` rows
   removed, and the active table re-read.

Unblock (deactivate or delete), and the expiry sweep for a temporary block,
remove exactly that binding by its comment and re-read.

Each router's answer is stored (``DeviceAccessRouterBlock``) before anyone
is told about it, because the binding outlives the request and has to be
found again to be taken off.

## What this deliberately does not do

* **Controller-managed venues (Omada).** A synthetic controller row has no
  RouterOS to connect to; the controller's own per-client block is a
  different path that this change leaves exactly as it was. Those rows are
  skipped here -- not recorded, not counted.
* **Anonymous guests with private Wi-Fi addresses.** A phone that
  randomises its MAC per network comes back as a new device; forgetting the
  network is enough. A MAC block is reliable for hardware the venue knows
  (a smart TV, a laptop, an employee's own device), not as a ban on a
  person. The person-level block is the identifier rule, enforced at
  sign-in.
* **Fail the rule because a router failed.** The rule is committed first,
  exactly as ``create_guest_rule`` does: barring the next sign-in is the
  half the platform can always deliver. A router that could not be reached
  is recorded ``failed`` with its reason and can be retried.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.vendor_capabilities import is_controller_managed

from .constants import BlockEnforcementStatus
from .device_adapters import GuestAccessCredentials, get_guest_access_adapter
from .exceptions import UnsupportedGuestAccessVendorError

logger = logging.getLogger(__name__)

#: ``comment=`` prefix of every binding this module writes. The gateway
#: refuses any other shape (``mikrotik_adapter.DEVICE_BLOCK_MARKER_PREFIX``).
DEVICE_BLOCK_MARKER_PREFIX = "cloudguest-devblock:"


def device_block_marker(rule_id: uuid.UUID) -> str:
    return f"{DEVICE_BLOCK_MARKER_PREFIX}{rule_id}"


class DeviceBlockRouterRow(Protocol):
    id: uuid.UUID
    vendor: str
    api_username: str | None
    management_ip_address: str | None
    public_ip_address: str | None
    location_id: uuid.UUID | None


class RouterScopeLookupProtocol(Protocol):
    """Satisfied structurally by ``app.domains.router.service.RouterService``."""

    async def list_routers_in_scope(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> Sequence[DeviceBlockRouterRow]: ...

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> DeviceBlockRouterRow: ...

    def get_decrypted_api_secret(self, router: DeviceBlockRouterRow) -> str | None: ...


class RouterBlockRecord(Protocol):
    """The fields a release needs off a stored ``DeviceAccessRouterBlock``."""

    rule_id: uuid.UUID
    router_id: uuid.UUID
    mac_address: str


@dataclass(frozen=True, slots=True)
class RouterDeviceBlockOutcome:
    """What one router did about one device rule.

    ``status`` is a :class:`BlockEnforcementStatus` value:

    * ``enforced`` -- the binding read back and no live session survived;
    * ``failed`` -- no credentials, unreachable, refused, or the session was
      still in the active table after removal (the binding may be there:
      the row stays releasable);
    * ``not_applicable`` -- the router runs no hotspot, so nothing was
      written there.
    """

    router_id: uuid.UUID
    location_id: uuid.UUID | None
    status: str
    sessions_ended: int = 0
    error_message: str | None = None

    @property
    def blocked(self) -> bool:
        return self.status == BlockEnforcementStatus.ENFORCED.value


@dataclass(frozen=True, slots=True)
class RouterDeviceReleaseOutcome:
    released: bool
    error_message: str | None = None


class RouterDeviceBlocker:
    """Writes and removes durable device blocks on MikroTik routers.

    Never raises for a device failure: each router's answer is returned, so
    one unreachable router cannot hide what the others did. Raises only for
    a programming error (a bad MAC reaching the gateway)."""

    def __init__(
        self,
        *,
        router_lookup: RouterScopeLookupProtocol,
        adapter_factory: object = None,
    ) -> None:
        self.router_lookup = router_lookup
        self._adapter_factory = adapter_factory or get_guest_access_adapter

    def _credentials(
        self, router: DeviceBlockRouterRow
    ) -> GuestAccessCredentials | None:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            return None
        return GuestAccessCredentials(
            host=host, username=router.api_username, password=secret
        )

    def _adapter_for(self, router: DeviceBlockRouterRow):  # noqa: ANN202
        """The RouterOS adapter, or ``None`` for a router this module does
        not write to (controller-managed, or a vendor with no adapter)."""
        if is_controller_managed(router):
            return None
        try:
            return self._adapter_factory(router.vendor)  # type: ignore[operator]
        except UnsupportedGuestAccessVendorError:
            return None

    async def block(
        self,
        *,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        mac_address: str,
    ) -> list[RouterDeviceBlockOutcome]:
        routers = await self.router_lookup.list_routers_in_scope(
            organization_id=organization_id, location_id=location_id
        )
        marker = device_block_marker(rule_id)
        outcomes: list[RouterDeviceBlockOutcome] = []
        for router in routers:
            adapter = self._adapter_for(router)
            if adapter is None:
                continue
            outcomes.append(await self._block_one(router, adapter, mac_address, marker))
        logger.info(
            "device_access_rule_router_blocks",
            extra={
                "event_rule_id": str(rule_id),
                "event_routers": len(outcomes),
                "event_enforced": sum(1 for o in outcomes if o.blocked),
            },
        )
        return outcomes

    async def _block_one(
        self,
        router: DeviceBlockRouterRow,
        adapter: object,
        mac_address: str,
        marker: str,
    ) -> RouterDeviceBlockOutcome:
        credentials = self._credentials(router)
        if credentials is None:
            return RouterDeviceBlockOutcome(
                router_id=router.id,
                location_id=router.location_id,
                status=BlockEnforcementStatus.FAILED.value,
                error_message=(
                    "This router has no stored API address or credentials, so "
                    "the block could not be written to it."
                ),
            )
        try:
            result = await adapter.block_device(  # type: ignore[attr-defined]
                credentials, mac_address=mac_address, marker=marker
            )
        except Exception as exc:  # noqa: BLE001 -- recorded per router
            logger.warning(
                "device_access_rule_router_block_failed",
                extra={"event_router_id": str(router.id), "event_error": str(exc)},
            )
            return RouterDeviceBlockOutcome(
                router_id=router.id,
                location_id=router.location_id,
                status=BlockEnforcementStatus.FAILED.value,
                error_message=str(exc),
            )
        if not result.binding_written:
            return RouterDeviceBlockOutcome(
                router_id=router.id,
                location_id=router.location_id,
                status=BlockEnforcementStatus.NOT_APPLICABLE.value,
                error_message="This router runs no guest login page, so there was "
                "nothing to block on it.",
            )
        if result.still_active:
            return RouterDeviceBlockOutcome(
                router_id=router.id,
                location_id=router.location_id,
                status=BlockEnforcementStatus.FAILED.value,
                sessions_ended=result.sessions_removed,
                error_message=(
                    "The block was written, but the router still lists the "
                    "device as signed in."
                ),
            )
        note = None
        if result.other_bindings or not result.first_in_order:
            note = (
                "Blocked. This device also has another entry on the router "
                f"({', '.join(result.other_bindings) or 'placed earlier'}) that "
                "was left as it was."
            )
        return RouterDeviceBlockOutcome(
            router_id=router.id,
            location_id=router.location_id,
            status=BlockEnforcementStatus.ENFORCED.value,
            sessions_ended=result.sessions_removed,
            error_message=note,
        )

    async def release(
        self, records: Sequence[RouterBlockRecord]
    ) -> list[tuple[RouterBlockRecord, RouterDeviceReleaseOutcome]]:
        """Remove the binding each record names. Never raises: a release
        that did not land is returned as such, and the caller leaves the
        row open for the sweep to retry."""
        results: list[tuple[RouterBlockRecord, RouterDeviceReleaseOutcome]] = []
        for record in records:
            results.append((record, await self._release_one(record)))
        return results

    async def _release_one(
        self, record: RouterBlockRecord
    ) -> RouterDeviceReleaseOutcome:
        try:
            router = await self.router_lookup.get_router(
                record.router_id, include_deleted=True
            )
        except RouterNotFoundError:
            return RouterDeviceReleaseOutcome(
                released=True,
                error_message="The router no longer exists here; nothing to remove.",
            )
        adapter = self._adapter_for(router)
        if adapter is None:
            return RouterDeviceReleaseOutcome(
                released=True,
                error_message="This router is no longer managed over RouterOS.",
            )
        credentials = self._credentials(router)
        if credentials is None:
            return RouterDeviceReleaseOutcome(
                released=False,
                error_message="This router has no stored API address or credentials.",
            )
        try:
            result = await adapter.unblock_device(  # type: ignore[attr-defined]
                credentials,
                mac_address=record.mac_address,
                marker=device_block_marker(record.rule_id),
            )
        except Exception as exc:  # noqa: BLE001 -- recorded on the row
            return RouterDeviceReleaseOutcome(released=False, error_message=str(exc))
        if result.remaining:
            return RouterDeviceReleaseOutcome(
                released=False,
                error_message="The block was removed but is still on the router.",
            )
        return RouterDeviceReleaseOutcome(released=True)


__all__ = [
    "DEVICE_BLOCK_MARKER_PREFIX",
    "RouterDeviceBlockOutcome",
    "RouterDeviceBlocker",
    "RouterDeviceReleaseOutcome",
    "device_block_marker",
]

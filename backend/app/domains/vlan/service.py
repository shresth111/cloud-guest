"""VLAN Management business logic: per-router VLAN inventory CRUD.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## Live device push

``push_vlan_to_device`` realizes a VLAN on its router over the RouterOS
API, through ``device_adapters``. This paragraph used to say the opposite
-- "no live device push in this pass ... this domain has no
``device_adapters.py``" -- and stayed after the adapter was added, which
is exactly the kind of stale claim that makes a docstring worse than
none. Creation still writes only a row, deliberately: renaming a VLAN must
not be able to fail with a connection error.

## NAT / Internet Access

``nat_enabled`` decides whether the push also realizes a source-NAT
masquerade rule for the VLAN's own ``cidr`` on the router's real WAN
interface. Without it a pushed VLAN is a complete *local* network and
nothing more -- guests get a lease, a gateway, and no route off the
router, with no error anywhere to say so.

Both directions are part of the same push: NAT on applies the rule, NAT
off removes it. That is what makes the toggle honest -- were the disabled
case a no-op, turning NAT off would leave the last-pushed rule
masquerading a network the operator has since decided must not reach the
internet, and the push would report success.

The WAN interface is never stored or assumed. It is derived from the
router's own live default route by the vendor adapter
(``mikrotik_adapter.resolve_wan_interface``), because nothing here knows
which port a given site's uplink is in, and a hardcoded ``"WAN"``/
``"ether1"`` would be wrong at the first site that names its ports
differently. When the router's state does not identify one, the push
fails with ``VlanNatWanInterfaceUnresolvedError`` rather than guessing.
This is the same rule ``network_config.wan.renderers
._uplink_discovery_statements`` applies device-side -- active default
route, verified to be a real interface, degrade rather than guess --
arrived at independently and worth keeping aligned.

**This rule coexists with the router-wide one, and does not replace
it.** ``network_config.renderers.render_guest_data_path`` ships a
masquerade scoped by ``out-interface`` alone, marked
``comment="cloudguest-nat-live"``, to every enrolled router. The two
never touch: each finds its own rule by its own comment, so neither
counts, re-points, or removes the other's. But the consequence is worth
stating plainly -- **on a router carrying that rule, turning
``nat_enabled`` off does not actually cut that VLAN off from the
internet**, because the router-wide rule still NATs everything leaving
the uplink. This push removes the VLAN's own rule and nothing else;
removing the shared one would take a whole venue offline, which is not a
per-VLAN toggle's decision to make.

**A pushed VLAN is not automatically a working VLAN.** ``/interface vlan``
on a bridge only segments traffic when that bridge has
``vlan-filtering=yes``; MikroTik's own documentation is explicit that with
``vlan-filtering=no`` "the bridge ignores VLAN tags, works in a
shared-VLAN-learning (SVL) mode, and cannot modify VLAN tags of packets".
This domain creates the interface and its address and reports exactly
that -- it does not turn on bridge VLAN filtering, which is a bridge-wide
change that drops untagged frames on any port without a correct PVID and
can lock an operator out of the router. See ``docs/vlan/FLOW.md``.

## Validation

``vlan_id`` must fall within IEEE 802.1Q's real 1-4094 usable range
(``validators.validate_vlan_id``) and must be unique per router among
non-deleted rows (``VlanIdAlreadyExistsError``). ``cidr``/
``gateway_ip_address``, when supplied, must be real, parseable values
(Python's own ``ipaddress`` module) -- a malformed value is rejected at
create/update time, never silently stored.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import VlanDevicePushStatus
from .device_adapters import VlanCredentials, get_vlan_adapter
from .events import VlanCreated, VlanDeleted, VlanPushed, VlanUpdated
from .exceptions import (
    CrossOrganizationVlanAccessError,
    VlanHotspotPushUnsupportedError,
    VlanIdAlreadyExistsError,
    VlanMissingCredentialsError,
    VlanMissingInterfaceError,
    VlanNatRequiresCidrError,
    VlanNotEnabledError,
    VlanNotFoundError,
)
from .models import Vlan
from .repository import VlanRepositoryProtocol
from .validators import validate_cidr, validate_gateway_ip_address, validate_vlan_id

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick every other domain's own ``_event_extra`` uses."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    # Declared because the device-push path really calls it. It was
    # previously left out, so this Protocol under-described what the
    # service requires: a collaborator could satisfy the annotation and
    # still blow up at runtime, and no type checker could see it coming.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class VlanService:
    """Core VLAN Management business logic."""

    def __init__(
        self,
        repository: VlanRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def create_vlan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        vlan_id: int,
        name: str,
        gateway_ip_address: str | None = None,
        cidr: str | None = None,
        interface: str | None = None,
        port_mode: str = "trunk",
        enable_hotspot: bool = False,
        nat_enabled: bool = False,
        description: str | None = None,
        is_enabled: bool = True,
    ) -> Vlan:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_vlan_id(vlan_id)
        validate_cidr(cidr)
        validate_gateway_ip_address(gateway_ip_address)
        if port_mode not in ("trunk", "access"):
            raise ValueError("port_mode must be 'trunk' or 'access'")
        existing = await self.repository.get_vlan_by_router_and_tag(router.id, vlan_id)
        if existing is not None:
            raise VlanIdAlreadyExistsError(router.id, vlan_id)

        vlan = await self.repository.create_vlan(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            vlan_id=vlan_id,
            name=name,
            gateway_ip_address=gateway_ip_address,
            cidr=cidr,
            interface=interface,
            port_mode=port_mode,
            enable_hotspot=enable_hotspot,
            nat_enabled=nat_enabled,
            description=description,
            is_enabled=is_enabled,
            # Written explicitly rather than left to the column default,
            # which only applies at INSERT: a freshly constructed row would
            # otherwise carry None until it round-trips through the
            # database, and "has this reached a device" must never read as
            # unknown.
            device_push_status=VlanDevicePushStatus.PENDING.value,
            created_by=actor_user_id,
        )
        event = VlanCreated(id=vlan.id, router_id=router.id, tag=vlan_id)
        logger.info("vlan_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_CREATED,
            entity_id=vlan.id,
            organization_id=vlan.organization_id,
            description=f"VLAN '{name}' (tag {vlan_id}) created for router {router.id}",
        )
        return vlan

    async def get_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Vlan:
        vlan = await self.repository.get_vlan_by_id(vlan_pk)
        if vlan is None:
            raise VlanNotFoundError(vlan_pk)
        if (
            requesting_organization_id is not None
            and vlan.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationVlanAccessError()
        return vlan

    async def list_vlans(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Vlan], object]:
        return await self.repository.list_vlans(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )

    async def list_vlans_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[Vlan]:
        """Every non-deleted VLAN for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full VLAN config, mirroring
        ``app.domains.dhcp.DhcpService.list_pools_for_router``'s identical
        shape."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_vlans_for_router(router_id)

    async def update_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> Vlan:
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        new_vlan_id = fields.get("vlan_id", vlan.vlan_id)
        if new_vlan_id != vlan.vlan_id:
            validate_vlan_id(new_vlan_id)
            existing = await self.repository.get_vlan_by_router_and_tag(
                vlan.router_id, new_vlan_id
            )
            if existing is not None and existing.id != vlan.id:
                raise VlanIdAlreadyExistsError(vlan.router_id, new_vlan_id)
        if "cidr" in fields:
            validate_cidr(fields["cidr"])
        if "gateway_ip_address" in fields:
            validate_gateway_ip_address(fields["gateway_ip_address"])
        if fields.get("port_mode") not in (None, "trunk", "access"):
            raise ValueError("port_mode must be 'trunk' or 'access'")

        updated = await self.repository.update_vlan(
            vlan, {**fields, "updated_by": actor_user_id}
        )
        event = VlanUpdated(id=updated.id)
        logger.info("vlan_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"VLAN '{updated.name}' updated",
        )
        return updated

    async def delete_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> Vlan:
        """Removes the VLAN from its router, then soft-deletes the row.

        Deleting used to soft-delete the row and nothing else, so a VLAN
        this platform had created went on carrying traffic on the device
        after the operator deleted it -- with nothing anywhere to say so.

        **The device comes first, and a device failure aborts the delete.**
        Removing the row while the interface is still live is exactly the
        drift this closes: the operator would believe it was gone, and
        nothing would ever reconcile it. Failing loudly leaves both sides
        consistent and the delete retryable.

        The trade-off is real and worth stating: a VLAN on a permanently
        unreachable router cannot be deleted through this path. That is the
        safer side to err on -- an undeletable row is visible, an orphaned
        live interface is not -- but it means decommissioning a dead router
        needs a deliberate escape hatch, which this method does not provide.
        """
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        await self._remove_from_device(
            vlan, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_vlan(vlan)
        event = VlanDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("vlan_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"VLAN '{deleted.name}' deleted",
        )
        return deleted

    async def push_vlan_to_device(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> Vlan:
        """Realizes one VLAN on its own router, over the RouterOS API.

        Until this existed, ``create_vlan`` wrote a row, returned 201, and
        the device was never contacted -- so "VLAN created" meant "a
        database row exists" and nothing more. Verified against the live
        fleet: one VLAN row, zero ``/interface vlan`` entries on the router.

        **Separate from create/update, deliberately.** Renaming a VLAN must
        not be able to fail with a connection error, and an operator must be
        able to retry a push without re-submitting the form.

        **Every precondition is checked before a socket is opened**, so a
        misconfigured row fails as a 4xx naming the problem rather than as a
        device timeout.

        **A failure is committed, then re-raised.** This is the one place
        this method deliberately does *not* copy ``qos.push_rule_to_device``:
        that method writes the failure and re-raises, but
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls back on any exception -- so its failure
        record is discarded and the row still reads ``pending`` after a real
        device failure, with ``device_push_error`` NULL. Its docstring
        claims the opposite, and the unit test that "proves" it uses an
        in-memory fake with no transaction. Committing explicitly before
        raising is what makes the record survive to be read.

        The exception then propagates as a real non-2xx. It must not become
        a ``200 {"success": false}``: the frontend interceptor unwraps
        ``data`` and never reads ``success``, so such a response is
        indistinguishable from success to every caller in the app.
        """
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )

        if not vlan.is_enabled:
            raise VlanNotEnabledError(vlan.id)
        if not vlan.interface:
            # render_vlan handles this by emitting a comment and skipping --
            # fine for a script, but on a direct push the same silence would
            # report success for a device that received nothing.
            raise VlanMissingInterfaceError(vlan.id)
        if vlan.enable_hotspot:
            # The toggle is six further RouterOS commands the adapter does
            # not implement. Pushing the interface and address while
            # dropping the portal would be a success message for a VLAN
            # whose guests never see one.
            raise VlanHotspotPushUnsupportedError(vlan.id)
        if vlan.nat_enabled and not vlan.cidr:
            # NAT is a rule about a source subnet, and this row has none.
            # Skipping the NAT step instead would report a successful push
            # for a VLAN whose guests still have no internet.
            raise VlanNatRequiresCidrError(vlan.id)

        router = await self.router_lookup.get_router(
            vlan.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_vlan_adapter(router.vendor)

        try:
            await adapter.configure_vlan(
                credentials,
                vlan_id=vlan.vlan_id,
                name=vlan.name,
                interface=vlan.interface,
                ip_cidr=self._device_address(vlan),
                port_mode=vlan.port_mode,
            )
            # NAT after the interface exists, so the push reads on the
            # device in the order the config depends: a masquerade rule for
            # a subnet no interface carries is a rule that matches nothing.
            #
            # The *disabled* case issues a delete rather than doing nothing,
            # and that is what makes "turning NAT off removes the rule"
            # true. Doing nothing would leave the last-pushed rule
            # masquerading a network the operator has since decided must
            # not reach the internet -- and this push would report success.
            # The delete is idempotent, so on a VLAN that never had NAT it
            # is a harmless no-op.
            if vlan.nat_enabled:
                await adapter.configure_nat_masquerade(
                    credentials, vlan_id=vlan.vlan_id, src_cidr=vlan.cidr
                )
            else:
                await adapter.delete_nat_masquerade(
                    credentials, vlan_id=vlan.vlan_id
                )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_vlan(
                vlan,
                {
                    "device_push_status": VlanDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            raise

        updated = await self.repository.update_vlan(
            vlan,
            {
                "device_push_status": VlanDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = VlanPushed(
            id=updated.id, router_id=updated.router_id, port_mode=updated.port_mode
        )
        logger.info("vlan_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"VLAN {updated.vlan_id} ('{updated.name}') pushed to router "
                f"{updated.router_id} in {updated.port_mode} mode"
            ),
        )
        return updated

    async def _remove_from_device(
        self, vlan: Vlan, *, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Tears the VLAN off its router, when there is anything there.

        Skipped entirely unless ``device_push_status`` is ``ACTIVE``: a row
        that was never pushed, or whose last push failed, has nothing on the
        device, and opening a connection to delete nothing would make every
        such delete fail whenever a router happened to be unreachable.
        """
        if vlan.device_push_status != VlanDevicePushStatus.ACTIVE.value:
            return
        if not vlan.interface:
            # Cannot be ACTIVE without one in practice -- push refuses
            # without an interface -- but the column is nullable, and
            # guessing an interface name to delete on would be worse than
            # doing nothing.
            return
        router = await self.router_lookup.get_router(
            vlan.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_vlan_adapter(router.vendor)
        # The exact reverse of the push order: NAT comes off first, while
        # the interface it references is still there, then the interface.
        #
        # Unconditional, not gated on ``nat_enabled``. The flag is current
        # intent; the rule on the device is history. A VLAN pushed with NAT
        # on and later switched off without a re-push still has its rule,
        # and reading the flag would leave exactly that rule behind on a
        # subnet that no longer exists. Removing what is already absent is
        # a no-op.
        await adapter.delete_nat_masquerade(credentials, vlan_id=vlan.vlan_id)
        await adapter.delete_vlan(
            credentials,
            vlan_id=vlan.vlan_id,
            name=vlan.name,
            interface=vlan.interface,
            ip_cidr=self._device_address(vlan),
            port_mode=vlan.port_mode,
        )

    @staticmethod
    def _device_address(vlan: Vlan) -> str | None:
        """The address line the device should carry, matching
        ``renderers._vlan_address_line`` exactly.

        When a gateway is set the router's own address is the *gateway*
        inside the subnet, not the network address -- sending ``cidr`` here
        would put the router at ``.0``. The two paths must agree: a VLAN
        pushed directly and the same VLAN rendered into a config script have
        to produce the same device state.
        """
        if not vlan.cidr:
            return None
        if vlan.gateway_ip_address:
            return f"{vlan.gateway_ip_address}/{vlan.cidr.split('/')[-1]}"
        return vlan.cidr

    def _resolve_device_credentials(self, router: Router) -> VlanCredentials:
        """Raise rather than guess -- mirrors ``qos``/``queue_management``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise VlanMissingCredentialsError(router.id)
        return VlanCredentials(
            host=host, username=router.api_username, password=secret
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="vlan",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "VlanService"]

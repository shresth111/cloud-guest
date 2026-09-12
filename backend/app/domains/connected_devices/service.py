"""Connected Device Management business logic: real per-router device
sync (DHCP lease/ARP), manual disconnect, and admin actions (comment,
block/unblock/whitelist).

## Composition, not duplication, with three other domains

* ``app.domains.router`` -- ``RouterLookupProtocol`` supplies a router's
  own connection fields and already-decrypted API secret, identical to
  every other domain in this codebase.
* ``app.domains.guest_access`` -- ``GuestAccessProtocol`` (satisfied
  structurally by the real ``GuestAccessService``) creates/removes a real
  ``DeviceAccessRule`` row for block/unblock/whitelist; this module never
  reimplements access-rule precedence.
* ``app.domains.guest`` -- ``GuestLookupProtocol`` (satisfied
  structurally by the real ``GuestRepository``) is a read-only
  cross-reference against ``GuestDevice``/``GuestSession`` for "Session
  Association"/"Guest Association"; this module never creates or
  mutates a guest, device, or session row.

## Per-router vendor adapter resolution

Mirrors ``app.domains.isp.service.IspService``'s own "resolve per-router
from ``Router.vendor`` via ``device_adapter_resolver``, never fix one
adapter at construction time" convention exactly.

## Sync semantics: a device that drops off is marked inactive, never deleted

A device absent from the router's own DHCP-lease/ARP tables on
a given sync tick has its ``is_active`` flipped to ``False`` -- its row
survives (so "guest association"/"comment"/history-adjacent context
isn't lost the moment someone unplugs a laptop), never soft-deleted by
the sync itself. Only an explicit admin ``delete_device`` call removes a
row -- mirrors ``app.domains.router.models.Router.status``'s own
"offline is a real, persisted state, not a deletion" convention.

## Audit-volume judgment call

Mirrors ``app.domains.isp.service``'s own tiering exactly: routine sync
discovery/updates (potentially hundreds of devices per tick,
platform-wide) are **not** audited -- only real admin-initiated actions
(disconnect, delete, comment, block/unblock/whitelist) are, the identical
"moderate-volume, admin-relevant" profile every other domain's own
lifecycle events already carry.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

from .constants import (
    MONITORED_HARDWARE_LIVENESS_PING_COUNT,
    ConnectionType,
)
from .device_adapters import (
    DeviceCredentials,
    get_connected_device_adapter,
)
from .events import (
    ConnectedDeviceAccessRuleApplied,
    ConnectedDeviceDeleted,
    ConnectedDeviceDisconnected,
    ConnectedDeviceDiscovered,
    ConnectedDeviceUpdated,
)
from .exceptions import (
    ConnectedDeviceConnectionError,
    ConnectedDeviceMissingCredentialsError,
    ConnectedDeviceNotFoundError,
    ConnectedDeviceOperationError,
    CrossLocationConnectedDeviceAccessError,
    CrossOrganizationConnectedDeviceAccessError,
    UnsupportedConnectedDeviceVendorError,
)
from .models import ConnectedDevice
from .repository import ConnectedDeviceRepositoryProtocol
from .validators import vendor_from_mac

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


def _connection_type_for(is_wireless: bool | None) -> ConnectionType:
    """Maps an adapter's three-state wireless verdict onto the stored
    ``connection_type``, including the state that used to be lost.

    ``DiscoveredDevice.is_wireless`` is ``None`` when the router cannot
    report wireless association at all -- which is every router this
    platform deploys, because they are wired hEX lite boxes with no radio
    and the venue's Wi-Fi comes from separate access points we do not
    talk to.

    This used to be a two-branch expression
    (``WIRELESS if is_wireless else WIRED``), so ``None`` fell to
    ``WIRED``. That recorded a *positive, wrong claim* -- "this device is
    on a cable" -- for every Wi-Fi guest on the fleet, and it was
    indistinguishable in the API response from a genuine wired device.
    ``UNKNOWN`` already existed for precisely this case; it simply was
    never reachable.

    Existing rows repair themselves without a migration: the sync sweep
    writes ``connection_type`` unconditionally on every tick, so an active
    device's row is corrected within one sweep interval. Rows for devices
    that are no longer present keep their historical value, which is the
    correct behaviour for a historical record.
    """
    if is_wireless is None:
        return ConnectionType.UNKNOWN
    return ConnectionType.WIRELESS if is_wireless else ConnectionType.WIRED


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class GuestAccessProtocol(Protocol):
    """The subset of ``app.domains.guest_access.service.GuestAccessService``
    this module needs for block/unblock/whitelist -- reused directly,
    never reimplemented."""

    async def create_device_rule(self, **fields: object) -> object: ...

    async def list_device_rules(self, **fields: object) -> object: ...

    async def deactivate_device_rule(self, **fields: object) -> object: ...


class GuestLookupProtocol(Protocol):
    """The subset of ``app.domains.guest.repository.GuestRepositoryProtocol``
    this module needs for a read-only guest/session cross-reference --
    reused directly, never reimplemented."""

    async def get_device_by_mac(self, mac_address: str) -> object | None: ...

    async def list_active_sessions_for_guest(self, guest_id: uuid.UUID) -> list: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class DeviceSyncSummary:
    discovered: int
    updated: int
    disconnected: int


@dataclass(frozen=True, slots=True)
class DeviceSyncSweepSummary:
    routers_synced: int
    routers_failed: int
    discovered: int
    updated: int
    disconnected: int


@dataclass(frozen=True, slots=True)
class MonitoredHardwareLivenessSummary:
    """The per-run outcome of ``run_monitored_hardware_liveness_sweep``.

    ``devices_up``/``devices_down`` are *this run's verdicts*, not global
    state: every probed device lands in exactly one (``received > 0`` ->
    up, ``received == 0`` -> down). ``skipped`` are targets the sweep
    could not probe (no known IP yet -- the device has never been
    observed by a discovery sync, so there is no management address to
    ping). ``routers_failed`` are routers whose whole probe batch was
    skipped because the router itself was unreachable -- reported apart
    from ``skipped`` so "nothing was probed because the site is down"
    cannot be mistaken for "every device is down"."""

    routers_probed: int
    routers_failed: int
    devices_up: int
    devices_down: int
    skipped: int


# ============================================================================
# Service
# ============================================================================


class ConnectedDeviceService:
    """Core Connected Device Management business logic."""

    def __init__(
        self,
        repository: ConnectedDeviceRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        guest_access: GuestAccessProtocol,
        guest_lookup: GuestLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        device_adapter_resolver=get_connected_device_adapter,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.guest_access = guest_access
        self.guest_lookup = guest_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver
        # Constructor-injected while `requesting_organization_id` stays
        # per-method: an organization id is an *argument* (which tenant
        # this call is about, and a Celery task legitimately varies it
        # per call), whereas a location confinement is a *property of
        # the caller*, fixed for the request, and a security control.
        # Threading a security control through every method means every
        # method can forget it, silently. See
        # `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

    # ========================================================================
    # Reads
    # ========================================================================

    async def get_device(
        self,
        device_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ConnectedDevice:
        device = await self.repository.get_device_by_id(device_id)
        if device is None:
            raise ConnectedDeviceNotFoundError(device_id)
        if (
            requesting_organization_id is not None
            and device.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationConnectedDeviceAccessError()
        # Not enough on its own: this row is reached by its own id, so the
        # permission check had nothing to pin to and a LOCATION grant on
        # the caller's own site satisfied it.
        enforce_entity_location(
            entity_location_id=getattr(device, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationConnectedDeviceAccessError(),
        )
        return device

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        guest_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConnectedDevice], object]:
        return await self.repository.list_devices(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            location_id=location_id,
            is_active=is_active,
            guest_id=guest_id,
            page=page,
            page_size=page_size,
        )

    # ========================================================================
    # Sync (real device I/O)
    # ========================================================================

    async def sync_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DeviceSyncSummary:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_credentials(router)
        adapter = self._get_device_adapter(router.vendor)
        discovered_devices = await adapter.discover_devices(credentials)

        existing = await self.repository.list_devices_for_router(router.id)
        existing_by_mac = {device.mac_address: device for device in existing}
        # Monitored devices' liveness fields are owned by the ping sweep
        # (``run_monitored_hardware_liveness_sweep``), not by this DHCP
        # discovery sync -- see that function's docstring for why a bound
        # lease is bookkeeping, not a live-device verdict. Fetching the
        # set once per router keeps every per-device branch below a single
        # ``mac_address in monitored_macs`` check.
        monitored_macs = await self.repository.list_monitored_macs_for_router(
            router.id
        )
        now = datetime.now(UTC)
        seen_macs: set[str] = set()
        discovered_count = 0
        updated_count = 0

        for discovered in discovered_devices:
            seen_macs.add(discovered.mac_address)
            vendor = vendor_from_mac(discovered.mac_address)
            connection_type = _connection_type_for(discovered.is_wireless)
            guest_id, guest_session_id = await self._resolve_guest_association(
                discovered.mac_address, router.id
            )
            existing_row = existing_by_mac.get(discovered.mac_address)
            if existing_row is None:
                created = await self.repository.create_device(
                    router_id=router.id,
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                    mac_address=discovered.mac_address,
                    ip_address=discovered.ip_address,
                    hostname=discovered.hostname,
                    vendor=vendor,
                    connection_type=connection_type.value,
                    interface=discovered.interface,
                    signal_strength_dbm=discovered.signal_strength_dbm,
                    is_active=True,
                    connected_at=now,
                    last_seen_at=now,
                    guest_id=guest_id,
                    guest_session_id=guest_session_id,
                )
                discovered_count += 1
                event = ConnectedDeviceDiscovered(
                    id=created.id,
                    router_id=router.id,
                    mac_address=discovered.mac_address,
                )
                logger.info("connected_device_discovered", extra=_event_extra(event))
            else:
                update: dict[str, object] = {
                    "ip_address": discovered.ip_address or existing_row.ip_address,
                    "hostname": discovered.hostname or existing_row.hostname,
                    "vendor": vendor or existing_row.vendor,
                    "connection_type": connection_type.value,
                    "interface": discovered.interface or existing_row.interface,
                    "signal_strength_dbm": discovered.signal_strength_dbm,
                    "guest_id": guest_id,
                    "guest_session_id": guest_session_id,
                }
                if discovered.mac_address not in monitored_macs:
                    # Only the discovery sync's own rows get its liveness
                    # verdict. A monitored device stays under the ping
                    # sweep's control -- ``is_active``/``connected_at``/
                    # ``last_seen_at`` reflect real ICMP reachability, not
                    # "the router still holds a lease for this MAC".
                    was_inactive = not existing_row.is_active
                    update.update(
                        {
                            "is_active": True,
                            "connected_at": now
                            if was_inactive
                            else existing_row.connected_at,
                            "last_seen_at": now,
                        }
                    )
                await self.repository.update_device(existing_row, update)
                updated_count += 1

        disconnected_count = 0
        for mac_address, row in existing_by_mac.items():
            if mac_address not in seen_macs and row.is_active:
                await self.repository.update_device(row, {"is_active": False})
                disconnected_count += 1

        return DeviceSyncSummary(
            discovered=discovered_count,
            updated=updated_count,
            disconnected=disconnected_count,
        )

    async def refresh_device(
        self,
        device_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ConnectedDevice:
        """Re-syncs the device's own router in full, then returns this
        one device's freshly-synced row."""
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        await self.sync_router(
            device.router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )

    # ========================================================================
    # Admin actions
    # ========================================================================

    async def disconnect_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ConnectedDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        router = await self.router_lookup.get_router(device.router_id)
        credentials = self._resolve_credentials(router)
        adapter = self._get_device_adapter(router.vendor)
        await adapter.disconnect_device(
            credentials, mac_address=device.mac_address, interface=device.interface
        )
        updated = await self.repository.update_device(device, {"is_active": False})
        event = ConnectedDeviceDisconnected(
            id=updated.id, router_id=updated.router_id, mac_address=updated.mac_address
        )
        logger.info("connected_device_disconnected", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONNECTED_DEVICE_DISCONNECTED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Connected device '{updated.mac_address}' disconnected",
        )
        return updated

    async def add_comment(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        comment: str,
    ) -> ConnectedDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_device(
            device, {"comment": comment, "updated_by": actor_user_id}
        )
        event = ConnectedDeviceUpdated(id=updated.id)
        logger.info("connected_device_comment_added", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONNECTED_DEVICE_COMMENT_ADDED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Comment added to connected device '{updated.mac_address}'",
        )
        return updated

    async def delete_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConnectedDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_device(device)
        event = ConnectedDeviceDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("connected_device_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONNECTED_DEVICE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Connected device '{deleted.mac_address}' deleted",
        )
        return deleted

    async def block_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> ConnectedDevice:
        return await self._apply_access_rule(
            device_id,
            rule_type="blocklist",
            action=AuditAction.CONNECTED_DEVICE_BLOCKED,
            reason=reason,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def whitelist_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> ConnectedDevice:
        return await self._apply_access_rule(
            device_id,
            rule_type="whitelist",
            action=AuditAction.CONNECTED_DEVICE_WHITELISTED,
            reason=reason,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def unblock_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConnectedDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        result = await self.guest_access.list_device_rules(
            requesting_organization_id=requesting_organization_id,
            mac_address=device.mac_address,
            rule_type="blocklist",
        )
        for rule in result.items:
            await self.guest_access.deactivate_device_rule(
                rule_id=rule.id,
                requesting_organization_id=requesting_organization_id,
                actor_user_id=actor_user_id,
            )
        event = ConnectedDeviceAccessRuleApplied(
            id=device.id, mac_address=device.mac_address, rule_type="unblocked"
        )
        logger.info("connected_device_unblocked", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CONNECTED_DEVICE_UNBLOCKED,
            entity_id=device.id,
            organization_id=device.organization_id,
            description=f"Connected device '{device.mac_address}' unblocked",
        )
        return device

    async def _apply_access_rule(
        self,
        device_id: uuid.UUID,
        *,
        rule_type: str,
        action: AuditAction,
        reason: str | None,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConnectedDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        await self.guest_access.create_device_rule(
            organization_id=device.organization_id,
            requesting_organization_id=requesting_organization_id,
            location_id=device.location_id,
            mac_address=device.mac_address,
            rule_type=rule_type,
            reason=reason,
            expires_at=None,
            actor_user_id=actor_user_id,
        )
        event = ConnectedDeviceAccessRuleApplied(
            id=device.id, mac_address=device.mac_address, rule_type=rule_type
        )
        logger.info("connected_device_access_rule_applied", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            action,
            entity_id=device.id,
            organization_id=device.organization_id,
            description=(
                f"Connected device '{device.mac_address}' {rule_type} rule applied"
            ),
        )
        return device

    # ========================================================================
    # Internal helpers
    # ========================================================================

    def _resolve_credentials(self, router: Router) -> DeviceCredentials:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise ConnectedDeviceMissingCredentialsError(router.id)
        return DeviceCredentials(
            host=host, username=router.api_username, password=secret
        )

    async def _resolve_guest_association(
        self, mac_address: str, router_id: uuid.UUID
    ) -> tuple[uuid.UUID | None, uuid.UUID | None]:
        """Read-only cross-reference against ``app.domains.guest`` -- see
        module docstring. Never creates or mutates a guest/device/session
        row."""
        device = await self.guest_lookup.get_device_by_mac(mac_address)
        if device is None:
            return None, None
        sessions = await self.guest_lookup.list_active_sessions_for_guest(
            device.guest_id
        )
        matching = next(
            (
                session
                for session in sessions
                if session.device_id == device.id and session.router_id == router_id
            ),
            None,
        )
        return device.guest_id, (matching.id if matching else None)

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
            entity_type="connected_device",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


async def run_device_sync_sweep(
    repository: ConnectedDeviceRepositoryProtocol,
    router_lookup: RouterLookupProtocol,
    guest_access: GuestAccessProtocol,
    guest_lookup: GuestLookupProtocol,
    *,
    audit_writer: AuditLogWriter | None = None,
    device_adapter_resolver=get_connected_device_adapter,
    organization_id: uuid.UUID | None = None,
    routers: list[Router] | None = None,
) -> DeviceSyncSweepSummary:
    """The platform-wide device-sync sweep
    ``tasks.run_connected_device_sync_sweep`` (Celery Beat) drives --
    pulled out to module scope for the identical "Celery task + test
    suite share one real implementation, no live Postgres needed for the
    latter" reason ``app.domains.isp.service.run_health_check_sweep`` was.
    Syncs every enabled router platform-wide, one at a time, with
    **per-router failure isolation**: a router that's unreachable/
    misconfigured is caught, logged
    (``connected_device_sync_sweep_router_failed``), and skipped, never
    aborting the sweep for every other router -- mirrors
    ``app.domains.isp.service.run_health_check_sweep``'s identical
    per-item isolation contract.

    ``routers``, when passed explicitly, is synced instead of
    ``repository.list_routers_for_sync()``'s own full, platform-wide
    result -- lets ``tasks.sync_single_router_devices`` (the real
    per-router fan-out leaf task the Beat-scheduled coordinator dispatches
    one of per router, instead of this function looping over every router
    in one process/worker slot) reuse this exact same per-router sync
    logic for a single-element list. The default (``None``) preserves this
    function's original, platform-wide-sweep behavior for any caller --
    including this module's own test suite -- that still wants that."""
    service = ConnectedDeviceService(
        repository,
        router_lookup,
        guest_access,
        guest_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=device_adapter_resolver,
    )
    if routers is None:
        routers = await repository.list_routers_for_sync(
            organization_id=organization_id
        )
    routers_synced = 0
    routers_failed = 0
    discovered = 0
    updated = 0
    disconnected = 0
    for router in routers:
        try:
            summary = await service.sync_router(router.id)
            routers_synced += 1
            discovered += summary.discovered
            updated += summary.updated
            disconnected += summary.disconnected
        except Exception as exc:  # noqa: BLE001 -- per-router isolation, see docstring
            routers_failed += 1
            logger.warning(
                "connected_device_sync_sweep_router_failed",
                extra={"router_id": str(router.id), "error": str(exc)},
            )
    return DeviceSyncSweepSummary(
        routers_synced=routers_synced,
        routers_failed=routers_failed,
        discovered=discovered,
        updated=updated,
        disconnected=disconnected,
    )


def _resolve_liveness_credentials(
    router: Router, router_lookup: RouterLookupProtocol
) -> DeviceCredentials:
    """Builds ``DeviceCredentials`` for a liveness-probe router from the
    router's own connection fields -- the identical resolution
    ``ConnectedDeviceService._resolve_credentials`` performs for discovery,
    lifted to module scope so the sweep below needs no service instance."""
    host = router.management_ip_address or router.public_ip_address
    secret = router_lookup.get_decrypted_api_secret(router)
    if not host or not router.api_username or not secret:
        raise ConnectedDeviceMissingCredentialsError(router.id)
    return DeviceCredentials(
        host=host, username=router.api_username, password=secret
    )


async def run_monitored_hardware_liveness_sweep(
    repository: ConnectedDeviceRepositoryProtocol,
    router_lookup: RouterLookupProtocol,
    *,
    device_adapter_resolver=get_connected_device_adapter,
    ping_count: int = MONITORED_HARDWARE_LIVENESS_PING_COUNT,
) -> MonitoredHardwareLivenessSummary:
    """The fast, ping-driven liveness sweep that ``tasks
    .run_monitored_hardware_liveness_sweep`` (Celery Beat) drives -- pulled
    out to module scope for the same "Celery task + test suite share one
    real implementation" reason every other sweep function in this
    codebase is.

    ## Why this sweep exists at all

    The platform's monitored-hardware status is derived from
    ``connected_devices.is_active`` (see ``app.domains.monitored_hardware
    .service.MonitoredHardwareService.with_status``). Before this sweep,
    the ONLY writer of that flag was the DHCP-lease/ARP discovery sync --
    which treats a RouterOS ``bound`` lease as "device seen". RouterOS
    keeps a lease ``bound`` for a client that powered off without
    releasing until the lease time elapses, so a venue access point that
    physically died stayed UP on the dashboard for (lease time + one
    discovery interval) -- the "AP Hall Lobby is down but the console
    still says UP" bug this sweep is the real fix for. The discovery
    sync's age-window (see ``STALE_SIGHTING_AFTER_SECONDS``) catches a
    *stalled* sweep or an unreachable router, but it cannot distinguish a
    lease-bound-but-dead AP from a live one.

    ## The signal: ICMP through the uplink router

    A monitored device's management IP lives on the venue LAN behind its
    router -- unreachable from this backend directly. So this sweep pings
    each device *from the router that genuinely observed it* (the
    ``ConnectedDevice.router_id`` the target row carries), via the
    adapter's ``ping`` (RouterOS ``/tool/ping``), and writes the verdict
    straight to that device's own ``ConnectedDevice`` row:
    ``received > 0`` -> ``is_active=True`` with ``connected_at`` (re)set
    and ``last_seen_at`` refreshed; ``received == 0`` -> ``is_active=
    False`` with ``last_seen_at`` deliberately untouched (it must keep
    meaning "last time we confirmed it alive", never the time a failed
    probe ran). ``MonitoredHardwareService.with_status`` then reports the
    existing derived UP/DOWN within one sweep tick (~30s) of a real power
    loss -- no waiting out the lease.

    ## Per-router isolation, and why a router failure skips not downs

    Each router's probe batch is independent: an unreachable/misconfigured
    router is caught, logged
    (``connected_device_liveness_sweep_router_failed``), and skipped --
    never aborting the sweep for every other router, and never writing
    false DOWN verdicts for an entire venue whose uplink (not its devices)
    is what failed. That router's devices keep their previous state and
    age out through the discovery sync's existing stale-sighting window
    instead. This mirrors ``run_device_sync_sweep``'s identical
    per-router isolation contract.

    ## Why the discovery sync no longer overrides monitored rows

    ``sync_router`` (above) fetches
    ``repository.list_monitored_macs_for_router`` and skips the liveness
    fields on those rows -- otherwise the 15-minute discovery sync would
    keep marking a lease-bound monitored AP ``is_active=True`` between
    this sweep's ticks, and the dashboard would flicker UP/DOWN every
    sweep period instead of showing the ping verdict. Discovery still
    owns those rows' metadata (IP/hostname/interface/guest association);
    only the three liveness columns moved here.
    """
    targets = await repository.list_monitored_targets()
    by_router: dict[uuid.UUID, list[ConnectedDevice]] = {}
    for device, _hardware in targets:
        by_router.setdefault(device.router_id, []).append(device)

    routers_probed = 0
    routers_failed = 0
    devices_up = 0
    devices_down = 0
    skipped = 0

    for router_id, devices in by_router.items():
        try:
            router = await router_lookup.get_router(router_id)
            credentials = _resolve_liveness_credentials(router, router_lookup)
            adapter = device_adapter_resolver(router.vendor)
        except (
            ConnectedDeviceMissingCredentialsError,
            UnsupportedConnectedDeviceVendorError,
            RouterNotFoundError,
        ) as exc:
            routers_failed += 1
            logger.warning(
                "connected_device_liveness_sweep_router_failed",
                extra={"router_id": str(router_id), "error": str(exc)},
            )
            continue
        try:
            for device in devices:
                if not device.ip_address:
                    skipped += 1
                    continue
                result = await adapter.ping(
                    credentials, target=device.ip_address, count=ping_count
                )
                if result.received > 0:
                    was_inactive = not device.is_active
                    await repository.update_device(
                        device,
                        {
                            "is_active": True,
                            "connected_at": datetime.now(UTC)
                            if was_inactive
                            else device.connected_at,
                            "last_seen_at": datetime.now(UTC),
                        },
                    )
                    devices_up += 1
                else:
                    await repository.update_device(device, {"is_active": False})
                    devices_down += 1
            routers_probed += 1
        except (
            ConnectedDeviceConnectionError,
            ConnectedDeviceOperationError,
        ) as exc:
            # The router (not the devices) is the thing that failed --
            # skip the whole batch rather than writing false DOWNs for a
            # venue whose uplink just went silent. See module docstring.
            routers_failed += 1
            logger.warning(
                "connected_device_liveness_sweep_router_failed",
                extra={"router_id": str(router_id), "error": str(exc)},
            )
            continue

    return MonitoredHardwareLivenessSummary(
        routers_probed=routers_probed,
        routers_failed=routers_failed,
        devices_up=devices_up,
        devices_down=devices_down,
        skipped=skipped,
    )


__all__ = [
    "RouterLookupProtocol",
    "GuestAccessProtocol",
    "GuestLookupProtocol",
    "AuditLogWriter",
    "DeviceSyncSummary",
    "DeviceSyncSweepSummary",
    "MonitoredHardwareLivenessSummary",
    "ConnectedDeviceService",
    "run_device_sync_sweep",
    "run_monitored_hardware_liveness_sweep",
]

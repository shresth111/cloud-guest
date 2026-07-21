"""Connected Device Management business logic: real per-router device
sync (DHCP lease/ARP/wireless registration table), manual disconnect,
and admin actions (comment, block/unblock/whitelist).

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

A device absent from the router's own DHCP-lease/ARP/wireless tables on
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
from app.domains.router.models import Router

from .constants import ConnectionType
from .device_adapters import DeviceCredentials, get_connected_device_adapter
from .events import (
    ConnectedDeviceAccessRuleApplied,
    ConnectedDeviceDeleted,
    ConnectedDeviceDisconnected,
    ConnectedDeviceDiscovered,
    ConnectedDeviceUpdated,
)
from .exceptions import (
    ConnectedDeviceMissingCredentialsError,
    ConnectedDeviceNotFoundError,
    CrossOrganizationConnectedDeviceAccessError,
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
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.guest_access = guest_access
        self.guest_lookup = guest_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver

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
        return device

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConnectedDevice], object]:
        return await self.repository.list_devices(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            location_id=location_id,
            is_active=is_active,
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
        now = datetime.now(UTC)
        seen_macs: set[str] = set()
        discovered_count = 0
        updated_count = 0

        for discovered in discovered_devices:
            seen_macs.add(discovered.mac_address)
            vendor = vendor_from_mac(discovered.mac_address)
            connection_type = (
                ConnectionType.WIRELESS
                if discovered.is_wireless
                else ConnectionType.WIRED
            )
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
                was_inactive = not existing_row.is_active
                await self.repository.update_device(
                    existing_row,
                    {
                        "ip_address": discovered.ip_address or existing_row.ip_address,
                        "hostname": discovered.hostname or existing_row.hostname,
                        "vendor": vendor or existing_row.vendor,
                        "connection_type": connection_type.value,
                        "interface": discovered.interface or existing_row.interface,
                        "signal_strength_dbm": discovered.signal_strength_dbm,
                        "is_active": True,
                        "connected_at": now
                        if was_inactive
                        else existing_row.connected_at,
                        "last_seen_at": now,
                        "guest_id": guest_id,
                        "guest_session_id": guest_session_id,
                    },
                )
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
    per-item isolation contract."""
    service = ConnectedDeviceService(
        repository,
        router_lookup,
        guest_access,
        guest_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=device_adapter_resolver,
    )
    routers = await repository.list_routers_for_sync(organization_id=organization_id)
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


__all__ = [
    "RouterLookupProtocol",
    "GuestAccessProtocol",
    "GuestLookupProtocol",
    "AuditLogWriter",
    "DeviceSyncSummary",
    "DeviceSyncSweepSummary",
    "ConnectedDeviceService",
    "run_device_sync_sweep",
]

"""Monitored Hardware business logic: registration CRUD plus the honest,
derived status lookup this whole domain exists for -- see ``__init__.py``'s
own module docstring for the full write-up.

## Composition, not duplication

``LocationLookupProtocol``/``RouterLookupProtocol`` are the identical
narrow, duck-typed Protocol composition-over-duplication pattern
``app.domains.network_device.service`` already establishes.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import datetime
from typing import Protocol

from app.domains.location.models import Location
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import HardwareStatus
from .events import MonitoredHardwareDeleted, MonitoredHardwareRegistered
from .exceptions import DuplicateMonitoredHardwareError, MonitoredHardwareNotFoundError
from .models import MonitoredHardware
from .repository import MonitoredHardwareRepositoryProtocol
from .validators import validate_mac_address

logger = logging.getLogger(__name__)

# A device is considered reachable ("up") only if connected_devices' own
# sync sweep marked it is_active on its most recent pass. That sweep runs
# every CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS (900s/15min as of
# this writing) -- is_active is a live flag maintained by that sweep
# itself, not a timestamp this domain has to age out on its own, so no
# separate "recently seen" threshold is needed here at all: it's already
# correct by construction.


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


@dataclasses.dataclass(frozen=True, slots=True)
class HardwareWithStatus:
    """A ``MonitoredHardware`` row plus its derived status -- see module
    docstring. ``last_seen_at`` is only ever a real
    ``ConnectedDevice.last_seen_at`` value (or ``None`` when the device
    has never been observed), never invented."""

    device: MonitoredHardware
    status: HardwareStatus
    last_seen_at: datetime | None


class MonitoredHardwareService:
    """Core Monitored Hardware business logic."""

    def __init__(
        self,
        repository: MonitoredHardwareRepositoryProtocol,
        location_lookup: LocationLookupProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def register_device(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        name: str,
        mac_address: str,
        device_type: str,
        router_id: uuid.UUID | None = None,
        floor: str | None = None,
    ) -> MonitoredHardware:
        location = await self.location_lookup.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        if router_id is not None:
            await self.router_lookup.get_router(
                router_id, requesting_organization_id=location.organization_id
            )
        normalized_mac = validate_mac_address(mac_address)

        existing = await self.repository.get_device_by_mac(
            location.organization_id, normalized_mac
        )
        if existing is not None and not existing.is_deleted:
            raise DuplicateMonitoredHardwareError(normalized_mac)

        device = await self.repository.create_device(
            organization_id=location.organization_id,
            location_id=location.id,
            router_id=router_id,
            name=name,
            mac_address=normalized_mac,
            device_type=device_type,
            floor=floor,
            created_by=actor_user_id,
        )
        event = MonitoredHardwareRegistered(
            id=device.id, organization_id=device.organization_id
        )
        logger.info("monitored_hardware_registered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MONITORED_HARDWARE_CREATED,
            entity_id=device.id,
            organization_id=device.organization_id,
            description=f"Monitored hardware '{normalized_mac}' registered",
        )
        return device

    async def get_device(
        self,
        device_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> MonitoredHardware:
        device = await self.repository.get_device_by_id(device_id)
        if device is None:
            raise MonitoredHardwareNotFoundError(device_id)
        if (
            requesting_organization_id is not None
            and device.organization_id != requesting_organization_id
        ):
            raise MonitoredHardwareNotFoundError(device_id)
        return device

    async def with_status(self, device: MonitoredHardware) -> HardwareWithStatus:
        connected = await self.repository.get_connected_device_by_mac(
            device.location_id, device.mac_address
        )
        if connected is None:
            return HardwareWithStatus(
                device=device, status=HardwareStatus.UNKNOWN, last_seen_at=None
            )
        status = HardwareStatus.UP if connected.is_active else HardwareStatus.DOWN
        return HardwareWithStatus(
            device=device, status=status, last_seen_at=connected.last_seen_at
        )

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[HardwareWithStatus], object]:
        devices, meta = await self.repository.list_devices(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )
        return [await self.with_status(d) for d in devices], meta

    async def delete_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> MonitoredHardware:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_device(device)
        event = MonitoredHardwareDeleted(
            id=deleted.id, organization_id=deleted.organization_id
        )
        logger.info("monitored_hardware_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MONITORED_HARDWARE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Monitored hardware '{deleted.mac_address}' deleted",
        )
        return deleted

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
            entity_type="monitored_hardware",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "LocationLookupProtocol",
    "RouterLookupProtocol",
    "AuditLogWriter",
    "HardwareWithStatus",
    "MonitoredHardwareService",
]

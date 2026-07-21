"""Network Device (NAC) business logic: device registration CRUD and the
admin-assessed compliance-status workflow.

## Composition, not duplication

``LocationLookupProtocol``/``RouterLookupProtocol`` (satisfied
structurally by the real ``app.domains.location.service.LocationService``/
``app.domains.router.service.RouterService``) are the identical narrow,
duck-typed Protocol composition-over-duplication pattern every domain in
this codebase establishes. Vendor OUI lookup reuses
``app.domains.connected_devices.validators.vendor_from_mac`` directly --
see that function's own docstring for the real, intentionally-small OUI
table it looks up against; this domain does not maintain a second one.

## Compliance status is admin-assessed -- see ``__init__.py``'s own
## module docstring for the full honesty write-up

``set_compliance_status`` is the one operation that changes
``compliance_status`` -- always an explicit, admin-driven call, never a
computed side effect of anything else in this service.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.connected_devices.validators import vendor_from_mac
from app.domains.location.models import Location
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import ComplianceStatus
from .events import (
    NetworkDeviceComplianceStatusChanged,
    NetworkDeviceDeleted,
    NetworkDeviceRegistered,
    NetworkDeviceUpdated,
)
from .exceptions import (
    CrossOrganizationNetworkDeviceAccessError,
    DuplicateNetworkDeviceError,
    NetworkDeviceNotFoundError,
)
from .models import NetworkDevice
from .repository import NetworkDeviceRepositoryProtocol
from .validators import validate_mac_address

logger = logging.getLogger(__name__)


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


class NetworkDeviceService:
    """Core Network Device (NAC) business logic."""

    def __init__(
        self,
        repository: NetworkDeviceRepositoryProtocol,
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
        mac_address: str,
        router_id: uuid.UUID | None = None,
        vendor: str | None = None,
        device_type: str | None = None,
        comment: str | None = None,
        is_active: bool = True,
    ) -> NetworkDevice:
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
            raise DuplicateNetworkDeviceError(normalized_mac)

        resolved_vendor = vendor or vendor_from_mac(normalized_mac)

        device = await self.repository.create_device(
            organization_id=location.organization_id,
            location_id=location.id,
            router_id=router_id,
            mac_address=normalized_mac,
            vendor=resolved_vendor,
            device_type=device_type,
            compliance_status=ComplianceStatus.UNKNOWN.value,
            compliance_notes=None,
            last_reviewed_at=None,
            comment=comment,
            is_active=is_active,
            created_by=actor_user_id,
        )
        event = NetworkDeviceRegistered(
            id=device.id, organization_id=device.organization_id
        )
        logger.info("network_device_registered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.NETWORK_DEVICE_CREATED,
            entity_id=device.id,
            organization_id=device.organization_id,
            description=f"Network device '{normalized_mac}' registered",
        )
        return device

    async def get_device(
        self,
        device_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> NetworkDevice:
        device = await self.repository.get_device_by_id(device_id)
        if device is None:
            raise NetworkDeviceNotFoundError(device_id)
        if (
            requesting_organization_id is not None
            and device.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationNetworkDeviceAccessError()
        return device

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        compliance_status: ComplianceStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[NetworkDevice], object]:
        return await self.repository.list_devices(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            compliance_status=(
                compliance_status.value if compliance_status else None
            ),
            page=page,
            page_size=page_size,
        )

    async def update_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> NetworkDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        if "mac_address" in fields:
            fields["mac_address"] = validate_mac_address(fields["mac_address"])

        updated = await self.repository.update_device(
            device, {**fields, "updated_by": actor_user_id}
        )
        event = NetworkDeviceUpdated(id=updated.id)
        logger.info("network_device_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.NETWORK_DEVICE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Network device '{updated.mac_address}' updated",
        )
        return updated

    async def set_compliance_status(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        compliance_status: ComplianceStatus,
        compliance_notes: str | None = None,
    ) -> NetworkDevice:
        """The one operation that changes ``compliance_status`` -- always
        an explicit, admin-driven assessment (see module docstring)."""
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        previous_status = device.compliance_status
        updated = await self.repository.update_device(
            device,
            {
                "compliance_status": compliance_status.value,
                "compliance_notes": compliance_notes,
                "last_reviewed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = NetworkDeviceComplianceStatusChanged(
            id=updated.id,
            previous_status=previous_status,
            new_status=compliance_status.value,
        )
        logger.info(
            "network_device_compliance_status_changed", extra=_event_extra(event)
        )
        await self._audit(
            actor_user_id,
            AuditAction.NETWORK_DEVICE_COMPLIANCE_STATUS_CHANGED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"Network device '{updated.mac_address}' compliance status "
                f"changed: {previous_status} -> {compliance_status.value}"
            ),
        )
        return updated

    async def delete_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> NetworkDevice:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_device(device)
        event = NetworkDeviceDeleted(
            id=deleted.id, organization_id=deleted.organization_id
        )
        logger.info("network_device_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.NETWORK_DEVICE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Network device '{deleted.mac_address}' deleted",
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
            entity_type="network_device",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "LocationLookupProtocol",
    "RouterLookupProtocol",
    "AuditLogWriter",
    "NetworkDeviceService",
]

"""Data access layer for the Monitored Hardware domain.

Mirrors ``app.domains.network_device.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``MonitoredHardwareRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``MonitoredHardwareRepository``).

Also owns the one cross-domain read this whole feature is built on --
``get_connected_device_by_mac`` -- a plain, read-only lookup against
``app.domains.connected_devices.models.ConnectedDevice`` for the same
``mac_address``/``location_id``, used by the service layer to derive an
honest status (see ``__init__.py``'s own module docstring). This never
writes to that table -- ``connected_devices``' own sync sweep remains the
only writer.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.connected_devices.models import ConnectedDevice

from .models import MonitoredHardware


class MonitoredHardwareRepositoryProtocol(Protocol):
    async def create_device(self, **fields: object) -> MonitoredHardware: ...

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MonitoredHardware | None: ...

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MonitoredHardware | None: ...

    async def soft_delete_device(
        self, device: MonitoredHardware
    ) -> MonitoredHardware: ...

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[MonitoredHardware], PaginationMeta]: ...

    async def get_connected_device_by_mac(
        self, location_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None: ...


class MonitoredHardwareRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``MonitoredHardwareRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.devices = GenericRepository(MonitoredHardware, session)
        self.connected_devices = GenericRepository(ConnectedDevice, session)

    async def create_device(self, **fields: object) -> MonitoredHardware:
        return await self.devices.create(fields)

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MonitoredHardware | None:
        return await self.devices.get_by_id(device_id, include_deleted=include_deleted)

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MonitoredHardware | None:
        results = await self.devices.get_all(
            filters={"organization_id": organization_id, "mac_address": mac_address},
            limit=1,
        )
        return results[0] if results else None

    async def soft_delete_device(self, device: MonitoredHardware) -> MonitoredHardware:
        return await self.devices.soft_delete(device)

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[MonitoredHardware], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        return await self.devices.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
        )

    async def get_connected_device_by_mac(
        self, location_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None:
        results = await self.connected_devices.get_all(
            filters={"location_id": location_id, "mac_address": mac_address},
            limit=1,
        )
        return results[0] if results else None


__all__ = ["MonitoredHardwareRepositoryProtocol", "MonitoredHardwareRepository"]

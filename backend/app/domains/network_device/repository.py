"""Data access layer for the Network Device (NAC) domain.

Mirrors ``app.domains.dhcp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs
(``NetworkDeviceRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation (``NetworkDeviceRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import NetworkDevice


class NetworkDeviceRepositoryProtocol(Protocol):
    async def create_device(self, **fields: object) -> NetworkDevice: ...

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> NetworkDevice | None: ...

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> NetworkDevice | None: ...

    async def update_device(
        self, device: NetworkDevice, data: dict[str, object]
    ) -> NetworkDevice: ...

    async def soft_delete_device(self, device: NetworkDevice) -> NetworkDevice: ...

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        compliance_status: str | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[NetworkDevice], PaginationMeta]: ...


class NetworkDeviceRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``NetworkDeviceRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.devices = GenericRepository(NetworkDevice, session)

    async def create_device(self, **fields: object) -> NetworkDevice:
        return await self.devices.create(fields)

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> NetworkDevice | None:
        return await self.devices.get_by_id(device_id, include_deleted=include_deleted)

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> NetworkDevice | None:
        results = await self.devices.get_all(
            filters={"organization_id": organization_id, "mac_address": mac_address},
            limit=1,
        )
        return results[0] if results else None

    async def update_device(
        self, device: NetworkDevice, data: dict[str, object]
    ) -> NetworkDevice:
        return await self.devices.update(device, data)

    async def soft_delete_device(self, device: NetworkDevice) -> NetworkDevice:
        return await self.devices.soft_delete(device)

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        compliance_status: str | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[NetworkDevice], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if compliance_status is not None:
            filters["compliance_status"] = compliance_status
        return await self.devices.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )


__all__ = ["NetworkDeviceRepositoryProtocol", "NetworkDeviceRepository"]

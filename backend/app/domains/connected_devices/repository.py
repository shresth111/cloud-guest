"""Data access layer for the Connected Device Management domain.

Mirrors ``app.domains.isp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs
(``ConnectedDeviceRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``ConnectedDeviceRepository``), plus one hand-written query
``GenericRepository``'s equality/IN-filter support genuinely can't
express: ``list_routers_for_sync``'s own "every non-deleted router,
platform-wide" enumeration, mirroring
``app.domains.monitoring.repository.MonitoringRepository.list_routers``'s
identical "a domain owning its own read-only cross-domain router query,
not delegating to ``app.domains.router`` itself" precedent (there is no
platform-wide "list every router" method on ``RouterRepository`` itself
to delegate to).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.router.models import Router

from .models import ConnectedDevice


class ConnectedDeviceRepositoryProtocol(Protocol):
    async def create_device(self, **fields: object) -> ConnectedDevice: ...

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConnectedDevice | None: ...

    async def get_device_by_router_and_mac(
        self, router_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None: ...

    async def update_device(
        self, device: ConnectedDevice, data: dict[str, object]
    ) -> ConnectedDevice: ...

    async def soft_delete_device(self, device: ConnectedDevice) -> ConnectedDevice: ...

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ConnectedDevice], PaginationMeta]: ...

    async def list_devices_for_router(
        self, router_id: uuid.UUID
    ) -> list[ConnectedDevice]: ...

    async def list_routers_for_sync(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[Router]: ...


class ConnectedDeviceRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ConnectedDeviceRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.devices = GenericRepository(ConnectedDevice, session)

    async def create_device(self, **fields: object) -> ConnectedDevice:
        return await self.devices.create(fields)

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConnectedDevice | None:
        return await self.devices.get_by_id(device_id, include_deleted=include_deleted)

    async def get_device_by_router_and_mac(
        self, router_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None:
        results = await self.devices.get_all(
            filters={"router_id": router_id, "mac_address": mac_address}, limit=1
        )
        return results[0] if results else None

    async def update_device(
        self, device: ConnectedDevice, data: dict[str, object]
    ) -> ConnectedDevice:
        return await self.devices.update(device, data)

    async def soft_delete_device(self, device: ConnectedDevice) -> ConnectedDevice:
        return await self.devices.soft_delete(device)

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ConnectedDevice], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        if location_id is not None:
            filters["location_id"] = location_id
        if is_active is not None:
            filters["is_active"] = is_active
        return await self.devices.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_devices_for_router(
        self, router_id: uuid.UUID
    ) -> list[ConnectedDevice]:
        return await self.devices.get_all(filters={"router_id": router_id})

    async def list_routers_for_sync(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[Router]:
        statement = select(Router).where(Router.is_deleted.is_(False))
        if organization_id is not None:
            statement = statement.where(Router.organization_id == organization_id)
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = ["ConnectedDeviceRepositoryProtocol", "ConnectedDeviceRepository"]

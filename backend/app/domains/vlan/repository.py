"""Data access layer for the VLAN Management domain.

Mirrors ``app.domains.isp_routing.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``VlanRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``VlanRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import Vlan


class VlanRepositoryProtocol(Protocol):
    async def create_vlan(self, **fields: object) -> Vlan: ...

    async def get_vlan_by_id(
        self, vlan_pk: uuid.UUID, *, include_deleted: bool = False
    ) -> Vlan | None: ...

    async def get_vlan_by_router_and_tag(
        self, router_id: uuid.UUID, tag: int
    ) -> Vlan | None: ...

    async def update_vlan(self, vlan: Vlan, data: dict[str, object]) -> Vlan: ...

    async def soft_delete_vlan(self, vlan: Vlan) -> Vlan: ...

    async def list_vlans(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Vlan], PaginationMeta]: ...

    async def list_vlans_for_router(self, router_id: uuid.UUID) -> list[Vlan]: ...


class VlanRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``VlanRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.vlans = GenericRepository(Vlan, session)

    async def create_vlan(self, **fields: object) -> Vlan:
        return await self.vlans.create(fields)

    async def get_vlan_by_id(
        self, vlan_pk: uuid.UUID, *, include_deleted: bool = False
    ) -> Vlan | None:
        return await self.vlans.get_by_id(vlan_pk, include_deleted=include_deleted)

    async def get_vlan_by_router_and_tag(
        self, router_id: uuid.UUID, tag: int
    ) -> Vlan | None:
        results = await self.vlans.get_all(
            filters={"router_id": router_id, "vlan_id": tag}, limit=1
        )
        return results[0] if results else None

    async def update_vlan(self, vlan: Vlan, data: dict[str, object]) -> Vlan:
        return await self.vlans.update(vlan, data)

    async def soft_delete_vlan(self, vlan: Vlan) -> Vlan:
        return await self.vlans.soft_delete(vlan)

    async def list_vlans(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Vlan], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.vlans.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_vlans_for_router(self, router_id: uuid.UUID) -> list[Vlan]:
        """Every non-deleted VLAN for this router, unpaginated -- mirrors
        ``app.domains.dhcp.repository.DhcpRepository
        .list_pools_for_router``'s identical shape."""
        return await self.vlans.get_all(filters={"router_id": router_id})


__all__ = ["VlanRepositoryProtocol", "VlanRepository"]

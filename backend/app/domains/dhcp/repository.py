"""Data access layer for the DHCP Pool Management domain.

Mirrors ``app.domains.vlan.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs (``DhcpRepositoryProtocol``), and
a concrete, ``GenericRepository``-backed implementation
(``DhcpRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import DhcpPool


class DhcpRepositoryProtocol(Protocol):
    async def create_pool(self, **fields: object) -> DhcpPool: ...

    async def get_pool_by_id(
        self, pool_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DhcpPool | None: ...

    async def update_pool(
        self, pool: DhcpPool, data: dict[str, object]
    ) -> DhcpPool: ...

    async def soft_delete_pool(self, pool: DhcpPool) -> DhcpPool: ...

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DhcpPool], PaginationMeta]: ...

    async def list_pools_for_router(self, router_id: uuid.UUID) -> list[DhcpPool]: ...


class DhcpRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``DhcpRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.pools = GenericRepository(DhcpPool, session)

    async def create_pool(self, **fields: object) -> DhcpPool:
        return await self.pools.create(fields)

    async def get_pool_by_id(
        self, pool_id: uuid.UUID, *, include_deleted: bool = False
    ) -> DhcpPool | None:
        return await self.pools.get_by_id(pool_id, include_deleted=include_deleted)

    async def update_pool(self, pool: DhcpPool, data: dict[str, object]) -> DhcpPool:
        return await self.pools.update(pool, data)

    async def soft_delete_pool(self, pool: DhcpPool) -> DhcpPool:
        return await self.pools.soft_delete(pool)

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DhcpPool], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.pools.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_pools_for_router(self, router_id: uuid.UUID) -> list[DhcpPool]:
        """Every non-deleted pool for this router, regardless of
        ``interface`` -- ``GenericRepository``'s own equality-filter
        support silently skips ``None``-valued filters (would never
        express ``interface IS NULL``), so the "same interface, including
        NULL == NULL" grouping conflict detection needs is done in Python
        by the caller (``service.py``'s own ``_check_range_conflict``),
        not pushed down into this query."""
        return await self.pools.get_all(filters={"router_id": router_id})


__all__ = ["DhcpRepositoryProtocol", "DhcpRepository"]

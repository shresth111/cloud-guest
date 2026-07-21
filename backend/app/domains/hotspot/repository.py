"""Data access layer for the Hotspot Settings domain.

Mirrors ``app.domains.dhcp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs (``HotspotRepositoryProtocol``),
and a concrete, ``GenericRepository``-backed implementation
(``HotspotRepository``).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import HotspotProfile


class HotspotRepositoryProtocol(Protocol):
    async def create_profile(self, **fields: object) -> HotspotProfile: ...

    async def get_profile_by_id(
        self, profile_id: uuid.UUID, *, include_deleted: bool = False
    ) -> HotspotProfile | None: ...

    async def update_profile(
        self, profile: HotspotProfile, data: dict[str, object]
    ) -> HotspotProfile: ...

    async def soft_delete_profile(self, profile: HotspotProfile) -> HotspotProfile: ...

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[HotspotProfile], PaginationMeta]: ...

    async def list_profiles_for_router(
        self, router_id: uuid.UUID
    ) -> list[HotspotProfile]: ...


class HotspotRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``HotspotRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.profiles = GenericRepository(HotspotProfile, session)

    async def create_profile(self, **fields: object) -> HotspotProfile:
        return await self.profiles.create(fields)

    async def get_profile_by_id(
        self, profile_id: uuid.UUID, *, include_deleted: bool = False
    ) -> HotspotProfile | None:
        return await self.profiles.get_by_id(
            profile_id, include_deleted=include_deleted
        )

    async def update_profile(
        self, profile: HotspotProfile, data: dict[str, object]
    ) -> HotspotProfile:
        return await self.profiles.update(profile, data)

    async def soft_delete_profile(self, profile: HotspotProfile) -> HotspotProfile:
        return await self.profiles.soft_delete(profile)

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[HotspotProfile], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.profiles.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_profiles_for_router(
        self, router_id: uuid.UUID
    ) -> list[HotspotProfile]:
        """Every non-deleted profile for this router, unpaginated -- the
        real read source ``app.domains.network_config`` composes to
        render a router's full hotspot config, mirroring
        ``app.domains.dhcp.repository.DhcpRepository
        .list_pools_for_router``'s identical shape."""
        return await self.profiles.get_all(filters={"router_id": router_id})


__all__ = ["HotspotRepositoryProtocol", "HotspotRepository"]

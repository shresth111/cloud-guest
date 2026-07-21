"""Data access layer for the ISP Management domain.

Mirrors ``app.domains.queue_management.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``IspRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``IspRepository``) bundling both of this module's tables
behind one repository object, plus a handful of hand-written statements for
the few queries ``GenericRepository``'s equality/IN-filter support
genuinely can't express (the platform-wide health-check sweep's own "every
enabled link, across every router/organization" query).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .constants import IspLinkRole
from .models import IspHealthCheck, IspLink


class IspRepositoryProtocol(Protocol):
    # -- links -------------------------------------------------------------------
    async def create_link(self, **fields: object) -> IspLink: ...

    async def get_link_by_id(
        self, link_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspLink | None: ...

    async def update_link(self, link: IspLink, data: dict[str, object]) -> IspLink: ...

    async def soft_delete_link(self, link: IspLink) -> IspLink: ...

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[IspLink], PaginationMeta]: ...

    async def list_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]: ...

    async def get_active_uplink_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None: ...

    async def get_primary_link_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None: ...

    async def list_backup_links_for_router(
        self, router_id: uuid.UUID
    ) -> list[IspLink]: ...

    async def list_enabled_links_for_sweep(self) -> list[IspLink]: ...

    # -- health checks -------------------------------------------------------------
    async def create_health_check(self, **fields: object) -> IspHealthCheck: ...

    async def list_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
    ) -> tuple[list[IspHealthCheck], PaginationMeta]: ...


class IspRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``IspRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.links = GenericRepository(IspLink, session)
        self.health_checks = GenericRepository(IspHealthCheck, session)

    # -- links -------------------------------------------------------------------

    async def create_link(self, **fields: object) -> IspLink:
        return await self.links.create(fields)

    async def get_link_by_id(
        self, link_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspLink | None:
        return await self.links.get_by_id(link_id, include_deleted=include_deleted)

    async def update_link(self, link: IspLink, data: dict[str, object]) -> IspLink:
        return await self.links.update(link, data)

    async def soft_delete_link(self, link: IspLink) -> IspLink:
        return await self.links.soft_delete(link)

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[IspLink], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.links.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]:
        return await self.links.get_all(
            filters={"router_id": router_id},
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )

    async def get_active_uplink_for_router(
        self, router_id: uuid.UUID
    ) -> IspLink | None:
        results = await self.links.get_all(
            filters={"router_id": router_id, "is_active_uplink": True}, limit=1
        )
        return results[0] if results else None

    async def get_primary_link_for_router(self, router_id: uuid.UUID) -> IspLink | None:
        results = await self.links.get_all(
            filters={"router_id": router_id, "role": IspLinkRole.PRIMARY.value},
            limit=1,
        )
        return results[0] if results else None

    async def list_backup_links_for_router(self, router_id: uuid.UUID) -> list[IspLink]:
        return await self.links.get_all(
            filters={"router_id": router_id, "role": IspLinkRole.BACKUP.value},
            sort_by="priority",
            sort_order=SortOrder.ASC,
        )

    async def list_enabled_links_for_sweep(self) -> list[IspLink]:
        """Every enabled ``IspLink`` across every router/organization --
        the platform-wide "who needs a health check this tick" query the
        Celery Beat sweep drives. A plain equality-filtered
        ``GenericRepository.get_all`` already expresses this; no
        hand-written SQL needed (unlike a genuinely cross-table
        aggregate)."""
        return await self.links.get_all(filters={"is_enabled": True})

    # -- health checks -------------------------------------------------------------

    async def create_health_check(self, **fields: object) -> IspHealthCheck:
        return await self.health_checks.create(fields)

    async def list_health_checks_for_link(
        self,
        link_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
    ) -> tuple[list[IspHealthCheck], PaginationMeta]:
        return await self.health_checks.paginate(
            page=page,
            page_size=page_size,
            filters={"isp_link_id": link_id},
            sort_by="checked_at",
            sort_order=SortOrder.DESC,
        )


__all__ = ["IspRepositoryProtocol", "IspRepository"]

"""Data access layer for the Captive Portal domain.

Mirrors ``app.domains.voucher.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``CaptivePortalRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``CaptivePortalRepository``), plus a handful of hand-written statements
for the few queries ``GenericRepository``'s equality/IN-filter support
genuinely can't express -- notably, ``GenericRepository.get_all``/``exists``
silently *skip* any filter whose value is ``None`` (see
``app.database.utils.filters.apply_filters``), so "give me the row where
``location_id IS NULL``" cannot be expressed as a plain filters dict. Every
lookup that needs an explicit ``IS NULL`` predicate is therefore a small,
hand-written ``select`` here instead.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import CaptivePortalConfig


class CaptivePortalRepositoryProtocol(Protocol):
    async def create_config(self, **fields: object) -> CaptivePortalConfig: ...

    async def get_config(self, config_id: uuid.UUID) -> CaptivePortalConfig | None: ...

    async def update_config(
        self, config: CaptivePortalConfig, data: dict[str, object]
    ) -> CaptivePortalConfig: ...

    async def soft_delete_config(
        self, config: CaptivePortalConfig
    ) -> CaptivePortalConfig: ...

    async def list_configs(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[CaptivePortalConfig], PaginationMeta]: ...

    async def find_default_for_organization(
        self, organization_id: uuid.UUID
    ) -> CaptivePortalConfig | None: ...

    async def find_active_org_default(
        self, organization_id: uuid.UUID
    ) -> CaptivePortalConfig | None: ...

    async def find_active_for_location(
        self, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> CaptivePortalConfig | None: ...


class CaptivePortalRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``CaptivePortalRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.configs = GenericRepository(CaptivePortalConfig, session)

    async def create_config(self, **fields: object) -> CaptivePortalConfig:
        return await self.configs.create(fields)

    async def get_config(self, config_id: uuid.UUID) -> CaptivePortalConfig | None:
        return await self.configs.get_by_id(config_id)

    async def update_config(
        self, config: CaptivePortalConfig, data: dict[str, object]
    ) -> CaptivePortalConfig:
        return await self.configs.update(config, data)

    async def soft_delete_config(
        self, config: CaptivePortalConfig
    ) -> CaptivePortalConfig:
        return await self.configs.soft_delete(config)

    async def list_configs(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[CaptivePortalConfig], PaginationMeta]:
        return await self.configs.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def find_default_for_organization(
        self, organization_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        """The organization's current ``is_default=True`` org-level
        (``location_id IS NULL``) row, regardless of ``is_active`` -- used
        by ``CaptivePortalService._clear_existing_default`` to un-default
        it before a different row is promoted, so it must find it even if
        it happens to be inactive."""
        statement = select(CaptivePortalConfig).where(
            CaptivePortalConfig.organization_id == organization_id,
            CaptivePortalConfig.location_id.is_(None),
            CaptivePortalConfig.is_default.is_(True),
            CaptivePortalConfig.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def find_active_org_default(
        self, organization_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        """The organization's *active* default -- what
        ``CaptivePortalService.resolve_portal_config`` falls back to when
        no location-specific override applies."""
        statement = select(CaptivePortalConfig).where(
            CaptivePortalConfig.organization_id == organization_id,
            CaptivePortalConfig.location_id.is_(None),
            CaptivePortalConfig.is_default.is_(True),
            CaptivePortalConfig.is_active.is_(True),
            CaptivePortalConfig.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def find_active_for_location(
        self, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        """The most-recently-updated *active* config scoped to this exact
        location, if any -- the highest-precedence tier in
        ``CaptivePortalService.resolve_portal_config``.

        Ordered by ``updated_at`` descending as a deterministic tie-break:
        this module does not otherwise prevent more than one config being
        marked ``is_active=True`` for the same location (unlike
        ``is_default``, there is no dedicated single-active-per-location
        enforcement -- see ``service.py``'s module docstring), so a
        defensive, deterministic pick is needed regardless.
        """
        statement = (
            select(CaptivePortalConfig)
            .where(
                CaptivePortalConfig.organization_id == organization_id,
                CaptivePortalConfig.location_id == location_id,
                CaptivePortalConfig.is_active.is_(True),
                CaptivePortalConfig.is_deleted.is_(False),
            )
            .order_by(CaptivePortalConfig.updated_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()


__all__ = ["CaptivePortalRepositoryProtocol", "CaptivePortalRepository"]

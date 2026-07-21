"""Data access layer for the Device Synchronization domain.

Mirrors ``app.domains.isp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs (``DeviceSyncRepositoryProtocol``),
and a concrete, ``GenericRepository``-backed implementation
(``DeviceSyncRepository``). No ``update``/``soft_delete`` methods exist
at all -- ``DeviceSyncRun`` is create-and-read only (see ``models.py``'s
own module docstring).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import DeviceSyncRun


class DeviceSyncRepositoryProtocol(Protocol):
    async def create_run(self, **fields: object) -> DeviceSyncRun: ...

    async def get_run_by_id(self, run_id: uuid.UUID) -> DeviceSyncRun | None: ...

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[DeviceSyncRun], PaginationMeta]: ...


class DeviceSyncRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``DeviceSyncRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.runs = GenericRepository(DeviceSyncRun, session)

    async def create_run(self, **fields: object) -> DeviceSyncRun:
        return await self.runs.create(fields)

    async def get_run_by_id(self, run_id: uuid.UUID) -> DeviceSyncRun | None:
        return await self.runs.get_by_id(run_id)

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[DeviceSyncRun], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.runs.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by="started_at",
            sort_order=SortOrder.DESC,
        )


__all__ = ["DeviceSyncRepositoryProtocol", "DeviceSyncRepository"]

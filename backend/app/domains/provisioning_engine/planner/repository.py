"""Data access layer for router discovery snapshots.

Mirrors ``app.domains.readiness.repository``'s shape: a ``Protocol``
describing every operation the service layer needs, and a concrete
``GenericRepository``-backed implementation.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository

from .models import RouterSnapshot


class RouterSnapshotRepositoryProtocol(Protocol):
    async def create(self, data: dict[str, object]) -> RouterSnapshot: ...

    async def get_by_id(
        self, snapshot_id: uuid.UUID
    ) -> RouterSnapshot | None: ...

    async def get_for_router(
        self, router_id: uuid.UUID, snapshot_id: uuid.UUID
    ) -> RouterSnapshot | None: ...

    async def list_for_router(
        self, router_id: uuid.UUID, *, limit: int = 10
    ) -> list[RouterSnapshot]: ...

    async def get_latest_for_router(
        self, router_id: uuid.UUID
    ) -> RouterSnapshot | None: ...


class RouterSnapshotRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``RouterSnapshotRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.snapshots = GenericRepository(RouterSnapshot, session)

    async def create(self, data: dict[str, object]) -> RouterSnapshot:
        return await self.snapshots.create(data)

    async def get_by_id(self, snapshot_id: uuid.UUID) -> RouterSnapshot | None:
        return await self.snapshots.get_by_id(snapshot_id)

    async def get_for_router(
        self, router_id: uuid.UUID, snapshot_id: uuid.UUID
    ) -> RouterSnapshot | None:
        results = await self.snapshots.get_all(
            filters={"router_id": router_id, "id": snapshot_id}, limit=1
        )
        return results[0] if results else None

    async def list_for_router(
        self, router_id: uuid.UUID, *, limit: int = 10
    ) -> list[RouterSnapshot]:
        return await self.snapshots.get_all(
            filters={"router_id": router_id},
            sort_by="captured_at",
            sort_order=SortOrder.DESC,
            limit=limit,
        )

    async def get_latest_for_router(
        self, router_id: uuid.UUID
    ) -> RouterSnapshot | None:
        rows = await self.list_for_router(router_id, limit=1)
        return rows[0] if rows else None


__all__ = ["RouterSnapshotRepositoryProtocol", "RouterSnapshotRepository"]

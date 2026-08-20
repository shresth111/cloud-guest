"""Persistence for ``managed_router_resources``."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .constants import ManagedResourceStatus
from .managed_resource_models import ManagedRouterResource


class ManagedRouterResourceRepositoryProtocol(Protocol):
    async def create_many(
        self, rows: list[dict[str, object]]
    ) -> list[ManagedRouterResource]: ...

    async def list_for_plan(
        self, plan_id: uuid.UUID, *, router_id: uuid.UUID | None = None
    ) -> list[ManagedRouterResource]: ...

    async def mark_applied_for_plan(
        self, plan_id: uuid.UUID, *, router_id: uuid.UUID
    ) -> None: ...


class ManagedRouterResourceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.resources = GenericRepository(ManagedRouterResource, session)

    async def create_many(
        self, rows: list[dict[str, object]]
    ) -> list[ManagedRouterResource]:
        created: list[ManagedRouterResource] = []
        for row in rows:
            created.append(await self.resources.create(row))
        return created

    async def list_for_plan(
        self, plan_id: uuid.UUID, *, router_id: uuid.UUID | None = None
    ) -> list[ManagedRouterResource]:
        filters: dict[str, object] = {"plan_id": plan_id}
        if router_id is not None:
            filters["router_id"] = router_id
        return await self.resources.get_all(filters=filters, limit=500)

    async def mark_applied_for_plan(
        self, plan_id: uuid.UUID, *, router_id: uuid.UUID
    ) -> None:
        rows = await self.list_for_plan(plan_id, router_id=router_id)
        for row in rows:
            await self.resources.update(
                row,
                {
                    "status": ManagedResourceStatus.APPLIED.value,
                    "applied_at": datetime.now(UTC),
                },
            )


__all__ = [
    "ManagedRouterResourceRepositoryProtocol",
    "ManagedRouterResourceRepository",
]

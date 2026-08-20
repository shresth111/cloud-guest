"""Data access for ``verification_runs``."""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository

from .verification_models import VerificationRun


class VerificationRunRepositoryProtocol(Protocol):
    async def create(self, data: dict[str, object]) -> VerificationRun: ...

    async def list_for_run_group(
        self, router_id: uuid.UUID, run_group_id: uuid.UUID
    ) -> list[VerificationRun]: ...

    async def get_latest_run_group_id(
        self, router_id: uuid.UUID, *, scope: str
    ) -> uuid.UUID | None: ...

    async def list_latest_group_for_router(
        self, router_id: uuid.UUID, *, scope: str
    ) -> list[VerificationRun]: ...


class VerificationRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.runs = GenericRepository(VerificationRun, session)

    async def create(self, data: dict[str, object]) -> VerificationRun:
        return await self.runs.create(data)

    async def list_for_run_group(
        self, router_id: uuid.UUID, run_group_id: uuid.UUID
    ) -> list[VerificationRun]:
        return await self.runs.get_all(
            filters={"router_id": router_id, "run_group_id": run_group_id},
            sort_by="created_at",
            sort_order=SortOrder.ASC,
        )

    async def get_latest_run_group_id(
        self, router_id: uuid.UUID, *, scope: str
    ) -> uuid.UUID | None:
        rows = await self.runs.get_all(
            filters={"router_id": router_id, "scope": scope},
            sort_by="started_at",
            sort_order=SortOrder.DESC,
            limit=1,
        )
        if not rows:
            return None
        return rows[0].run_group_id

    async def list_latest_group_for_router(
        self, router_id: uuid.UUID, *, scope: str
    ) -> list[VerificationRun]:
        group_id = await self.get_latest_run_group_id(router_id, scope=scope)
        if group_id is None:
            return []
        return await self.list_for_run_group(router_id, group_id)


__all__ = ["VerificationRunRepositoryProtocol", "VerificationRunRepository"]

"""Persistence for ``configuration_plans``."""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository

from .plan_models import ConfigurationPlan


class ConfigurationPlanRepositoryProtocol(Protocol):
    async def create(self, data: dict[str, object]) -> ConfigurationPlan: ...

    async def get_by_id(
        self, plan_id: uuid.UUID, *, router_id: uuid.UUID | None = None
    ) -> ConfigurationPlan | None: ...

    async def update(
        self,
        plan: ConfigurationPlan,
        data: dict[str, object],
    ) -> ConfigurationPlan: ...


class ConfigurationPlanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.plans = GenericRepository(ConfigurationPlan, session)

    async def create(self, data: dict[str, object]) -> ConfigurationPlan:
        return await self.plans.create(data)

    async def get_by_id(
        self, plan_id: uuid.UUID, *, router_id: uuid.UUID | None = None
    ) -> ConfigurationPlan | None:
        filters: dict[str, object] = {"id": plan_id}
        if router_id is not None:
            filters["router_id"] = router_id
        rows = await self.plans.get_all(filters=filters, limit=1)
        return rows[0] if rows else None

    async def update(
        self, plan: ConfigurationPlan, data: dict[str, object]
    ) -> ConfigurationPlan:
        return await self.plans.update(plan, data)


__all__ = ["ConfigurationPlanRepositoryProtocol", "ConfigurationPlanRepository"]

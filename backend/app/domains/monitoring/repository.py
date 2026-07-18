"""Repository layer for the Monitoring domain."""

import uuid
from typing import Sequence
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.domains.monitoring.models import RouterMetric, SystemHealth

class MonitoringRepository(GenericRepository[RouterMetric]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(RouterMetric, session)
        self.health_repo = GenericRepository(SystemHealth, session)

    async def get_latest_metrics_for_router(self, router_id: uuid.UUID) -> RouterMetric | None:
        stmt = (
            select(RouterMetric)
            .where(RouterMetric.router_id == router_id)
            .order_by(desc(RouterMetric.created_at))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_metrics_history(self, router_id: uuid.UUID, limit: int = 100) -> Sequence[RouterMetric]:
        stmt = (
            select(RouterMetric)
            .where(RouterMetric.router_id == router_id)
            .order_by(desc(RouterMetric.created_at))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_all_system_health(self) -> Sequence[SystemHealth]:
        return await self.health_repo.get_all()

    async def update_component_health(self, component: str, status: str, details: dict) -> SystemHealth:
        stmt = select(SystemHealth).where(SystemHealth.component == component)
        result = await self.session.execute(stmt)
        health = result.scalar_one_or_none()
        if health:
            health.status = status
            health.details = details
            await self.session.flush()
            return health
        else:
            return await self.health_repo.create({"component": component, "status": status, "details": details})

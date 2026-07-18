"""Repository layer for the Analytics domain."""

import uuid
from datetime import datetime
from typing import Sequence
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.domains.analytics.models import AnalyticsAggregate

class AnalyticsRepository(GenericRepository[AnalyticsAggregate]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AnalyticsAggregate, session)

    async def get_aggregates(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> Sequence[AnalyticsAggregate]:
        filters = [
            AnalyticsAggregate.metric_name == metric_name,
            AnalyticsAggregate.timestamp >= start_time,
            AnalyticsAggregate.timestamp <= end_time,
        ]
        if organization_id:
            filters.append(AnalyticsAggregate.organization_id == organization_id)
        if location_id:
            filters.append(AnalyticsAggregate.location_id == location_id)

        stmt = (
            select(AnalyticsAggregate)
            .where(and_(*filters))
            .order_by(desc(AnalyticsAggregate.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

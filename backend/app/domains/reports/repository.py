"""Repository layer for the Reports domain."""

import uuid
from typing import Sequence
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.domains.reports.models import Report, ReportSchedule

class ReportsRepository(GenericRepository[Report]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Report, session)
        self.schedules_repo = GenericRepository(ReportSchedule, session)

    async def get_active_schedules(self) -> Sequence[ReportSchedule]:
        stmt = select(ReportSchedule).where(ReportSchedule.is_active == True)
        result = await self.schedules_repo.session.execute(stmt)
        return result.scalars().all()

    async def get_schedules_by_organization(self, organization_id: uuid.UUID) -> Sequence[ReportSchedule]:
        stmt = select(ReportSchedule).where(ReportSchedule.organization_id == organization_id)
        result = await self.schedules_repo.session.execute(stmt)
        return result.scalars().all()

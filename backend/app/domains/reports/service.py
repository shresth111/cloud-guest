"""Service layer for the Reports domain."""

import uuid
from datetime import datetime, UTC
from typing import Any, Sequence

from redis.asyncio import Redis
from app.domains.reports.repository import ReportsRepository
from app.domains.reports.models import Report, ReportSchedule
from app.domains.reports.exceptions import ReportNotFoundError, ReportScheduleNotFoundError

class ReportService:
    def __init__(self, repository: ReportsRepository, redis: Redis) -> None:
        self.repository = repository
        self.redis = redis

    async def generate_report_demand(
        self,
        name: str,
        report_type: str,
        file_format: str,
        parameters: dict[str, Any],
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
    ) -> Report:
        # Create pending report
        report_data = {
            "name": name,
            "report_type": report_type,
            "file_format": file_format,
            "parameters": parameters,
            "organization_id": organization_id,
            "location_id": location_id,
            "created_by": user_id,
            "status": "completed",  # Complete synchronously with mock asset link
            "file_url": f"https://assets.cloudguest.net/reports/{uuid.uuid4()}.{file_format}",
        }
        return await self.repository.create(report_data)

    async def create_schedule(
        self,
        name: str,
        report_type: str,
        file_format: str,
        frequency: str,
        recipients: list[str],
        parameters: dict[str, Any],
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
    ) -> ReportSchedule:
        schedule_data = {
            "name": name,
            "report_type": report_type,
            "file_format": file_format,
            "frequency": frequency,
            "recipients": recipients,
            "parameters": parameters,
            "organization_id": organization_id,
            "location_id": location_id,
            "created_by": user_id,
            "is_active": True,
            "next_run_at": datetime.now(UTC),
        }
        return await self.repository.schedules_repo.create(schedule_data)

    async def list_reports(self, limit: int = 50) -> Sequence[Report]:
        return await self.repository.get_all(limit=limit)

    async def get_schedules(self, organization_id: uuid.UUID) -> Sequence[ReportSchedule]:
        return await self.repository.get_schedules_by_organization(organization_id)

    async def delete_schedule(self, schedule_id: uuid.UUID) -> None:
        schedule = await self.repository.schedules_repo.get_by_id(schedule_id)
        if not schedule:
            raise ReportScheduleNotFoundError(schedule_id)
        await self.repository.schedules_repo.delete(schedule)

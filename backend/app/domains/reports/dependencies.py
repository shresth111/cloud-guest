"""FastAPI dependencies for the Reports domain."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.reports.repository import ReportsRepository
from app.domains.reports.service import ReportService

async def get_reports_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ReportsRepository:
    return ReportsRepository(db)

async def get_reports_service(
    repository: ReportsRepository = Depends(get_reports_repository),
    redis: Redis = Depends(get_redis_client),
) -> ReportService:
    return ReportService(repository, redis)

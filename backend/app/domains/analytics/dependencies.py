"""FastAPI dependencies for the Analytics domain."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.analytics.repository import AnalyticsRepository
from app.domains.analytics.service import AnalyticsService

async def get_analytics_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AnalyticsRepository:
    return AnalyticsRepository(db)

async def get_analytics_service(
    repository: AnalyticsRepository = Depends(get_analytics_repository),
    redis: Redis = Depends(get_redis_client),
) -> AnalyticsService:
    return AnalyticsService(repository, redis)

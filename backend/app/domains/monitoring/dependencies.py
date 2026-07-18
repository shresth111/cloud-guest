"""FastAPI dependencies for the Monitoring domain."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.monitoring.repository import MonitoringRepository
from app.domains.monitoring.service import MonitoringService

async def get_monitoring_repository(
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringRepository:
    return MonitoringRepository(db)

async def get_monitoring_service(
    repository: MonitoringRepository = Depends(get_monitoring_repository),
    redis: Redis = Depends(get_redis_client),
) -> MonitoringService:
    return MonitoringService(repository, redis)

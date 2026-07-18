"""FastAPI dependencies for the Alerts domain."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.alerts.repository import AlertsRepository
from app.domains.alerts.service import AlertService

async def get_alerts_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AlertsRepository:
    return AlertsRepository(db)

async def get_alerts_service(
    repository: AlertsRepository = Depends(get_alerts_repository),
    redis: Redis = Depends(get_redis_client),
) -> AlertService:
    return AlertService(repository, redis)

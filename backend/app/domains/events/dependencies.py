"""FastAPI dependencies for the Events domain."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.events.repository import EventsRepository
from app.domains.events.service import EventService

async def get_events_repository(
    db: AsyncSession = Depends(get_db_session),
) -> EventsRepository:
    return EventsRepository(db)

async def get_events_service(
    repository: EventsRepository = Depends(get_events_repository),
    redis: Redis = Depends(get_redis_client),
) -> EventService:
    return EventService(repository, redis)

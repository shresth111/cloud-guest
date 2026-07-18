"""Dependencies for the Subscription domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import SubscriptionRepository
from .service import SubscriptionService


async def get_subscription_repository(
    session: AsyncSession = Depends(get_db_session)
) -> SubscriptionRepository:
    return SubscriptionRepository(session)


async def get_subscription_service(
    repository: SubscriptionRepository = Depends(get_subscription_repository)
) -> SubscriptionService:
    return SubscriptionService(repository)

"""Dependencies for the Billing domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import BillingRepository
from .service import BillingService


async def get_billing_repository(
    session: AsyncSession = Depends(get_db_session)
) -> BillingRepository:
    return BillingRepository(session)


async def get_billing_service(
    repository: BillingRepository = Depends(get_billing_repository)
) -> BillingService:
    return BillingService(repository)

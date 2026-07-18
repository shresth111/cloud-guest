"""Dependencies for the Payment domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import PaymentRepository
from .service import PaymentService


async def get_payment_repository(
    session: AsyncSession = Depends(get_db_session)
) -> PaymentRepository:
    return PaymentRepository(session)


async def get_payment_service(
    repository: PaymentRepository = Depends(get_payment_repository)
) -> PaymentService:
    return PaymentService(repository)

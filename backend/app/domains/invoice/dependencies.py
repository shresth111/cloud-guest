"""Dependencies for the Invoice domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import InvoiceRepository
from .service import InvoiceService


async def get_invoice_repository(
    session: AsyncSession = Depends(get_db_session)
) -> InvoiceRepository:
    return InvoiceRepository(session)


async def get_invoice_service(
    repository: InvoiceRepository = Depends(get_invoice_repository)
) -> InvoiceService:
    return InvoiceService(repository)

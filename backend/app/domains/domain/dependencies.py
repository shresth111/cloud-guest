"""Dependencies for the Custom Domains domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import CustomDomainRepository
from .service import CustomDomainService


async def get_custom_domain_repository(
    session: AsyncSession = Depends(get_db_session)
) -> CustomDomainRepository:
    return CustomDomainRepository(session)


async def get_custom_domain_service(
    repository: CustomDomainRepository = Depends(get_custom_domain_repository)
) -> CustomDomainService:
    return CustomDomainService(repository)

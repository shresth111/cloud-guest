"""Dependencies for the Branding domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import BrandingRepository
from .service import BrandingService


async def get_branding_repository(
    session: AsyncSession = Depends(get_db_session)
) -> BrandingRepository:
    return BrandingRepository(session)


async def get_branding_service(
    repository: BrandingRepository = Depends(get_branding_repository)
) -> BrandingService:
    return BrandingService(repository)

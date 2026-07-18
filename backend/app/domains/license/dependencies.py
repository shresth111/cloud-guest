"""Dependencies for the License domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import LicenseRepository
from .service import LicenseService


async def get_license_repository(
    session: AsyncSession = Depends(get_db_session)
) -> LicenseRepository:
    return LicenseRepository(session)


async def get_license_service(
    repository: LicenseRepository = Depends(get_license_repository)
) -> LicenseService:
    return LicenseService(repository)

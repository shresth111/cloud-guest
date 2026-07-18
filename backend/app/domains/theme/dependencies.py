"""Dependencies for the Theme domain."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from .repository import ThemeRepository
from .service import ThemeService


async def get_theme_repository(
    session: AsyncSession = Depends(get_db_session)
) -> ThemeRepository:
    return ThemeRepository(session)


async def get_theme_service(
    repository: ThemeRepository = Depends(get_theme_repository)
) -> ThemeService:
    return ThemeService(repository)

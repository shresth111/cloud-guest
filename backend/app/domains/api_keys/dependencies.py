"""FastAPI dependencies for the API Keys domain."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .repository import ApiKeyRepository, ApiKeyRepositoryProtocol
from .service import ApiKeyService


def get_api_key_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ApiKeyRepositoryProtocol:
    return ApiKeyRepository(db)


def get_api_key_service(
    repository: ApiKeyRepositoryProtocol = Depends(get_api_key_repository),
) -> ApiKeyService:
    return ApiKeyService(repository)


__all__ = ["get_api_key_repository", "get_api_key_service"]

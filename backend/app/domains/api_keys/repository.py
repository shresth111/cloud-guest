"""Data access layer for the API Keys domain."""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import ApiKey


class ApiKeyRepositoryProtocol(Protocol):
    async def create_api_key(self, **fields: object) -> ApiKey: ...

    async def get_api_key_by_id(self, api_key_id: uuid.UUID) -> ApiKey | None: ...

    async def get_active_api_key_by_hash(self, key_hash: str) -> ApiKey | None: ...

    async def update_api_key(
        self, api_key: ApiKey, data: dict[str, object]
    ) -> ApiKey: ...

    async def list_api_keys(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ApiKey], PaginationMeta]: ...


class ApiKeyRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ApiKeyRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.api_keys = GenericRepository(ApiKey, session)

    async def create_api_key(self, **fields: object) -> ApiKey:
        return await self.api_keys.create(fields)

    async def get_api_key_by_id(self, api_key_id: uuid.UUID) -> ApiKey | None:
        return await self.api_keys.get_by_id(api_key_id)

    async def get_active_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        """``active`` here only means "not soft-deleted" -- expiry/
        revocation are real, distinct business states the service layer
        checks explicitly (see ``ApiKeyAuthenticationError``'s own
        docstring for why a mismatch and an expiry read identically to
        the caller), not folded into this lookup's own filter."""
        statement = select(ApiKey).where(
            ApiKey.is_deleted.is_(False), ApiKey.key_hash == key_hash
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def update_api_key(self, api_key: ApiKey, data: dict[str, object]) -> ApiKey:
        return await self.api_keys.update(api_key, data)

    async def list_api_keys(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ApiKey], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        return await self.api_keys.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=DEFAULT_SORT_FIELD,
            sort_order=SortOrder.DESC,
        )


__all__ = ["ApiKeyRepositoryProtocol", "ApiKeyRepository"]

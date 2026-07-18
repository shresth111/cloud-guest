"""Data access layer for the OTP domain.

Mirrors ``app.domains.wireguard.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``OtpRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``OtpRepository``) for this module's one table. No
hand-written SQL is needed -- ``GenericRepository``'s equality-filter +
sort + limit support is already exactly what "the latest matching row"
and "an admin-facing paginated list" both need.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import OtpRequest


class OtpRepositoryProtocol(Protocol):
    async def create_otp_request(self, **fields: object) -> OtpRequest: ...

    async def get_by_id(
        self, otp_request_id: uuid.UUID, *, include_deleted: bool = False
    ) -> OtpRequest | None: ...

    async def get_latest_for_identifier(
        self, identifier: str, purpose: str
    ) -> OtpRequest | None: ...

    async def update_otp_request(
        self, otp_request: OtpRequest, data: dict[str, object]
    ) -> OtpRequest: ...

    async def list_requests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[OtpRequest], PaginationMeta]: ...


class OtpRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``OtpRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.requests = GenericRepository(OtpRequest, session)

    async def create_otp_request(self, **fields: object) -> OtpRequest:
        return await self.requests.create(fields)

    async def get_by_id(
        self, otp_request_id: uuid.UUID, *, include_deleted: bool = False
    ) -> OtpRequest | None:
        return await self.requests.get_by_id(
            otp_request_id, include_deleted=include_deleted
        )

    async def get_latest_for_identifier(
        self, identifier: str, purpose: str
    ) -> OtpRequest | None:
        """The most recently created ``OtpRequest`` for this identifier +
        purpose, regardless of its state (expired/consumed/locked-out) --
        ``OtpService.verify_otp`` is what interprets state and raises the
        appropriate distinct exception (see that module's docstring)."""
        results = await self.requests.get_all(
            filters={"identifier": identifier, "purpose": purpose},
            sort_by="created_at",
            sort_order=SortOrder.DESC,
            limit=1,
        )
        return results[0] if results else None

    async def update_otp_request(
        self, otp_request: OtpRequest, data: dict[str, object]
    ) -> OtpRequest:
        return await self.requests.update(otp_request, data)

    async def list_requests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[OtpRequest], PaginationMeta]:
        return await self.requests.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )


__all__ = ["OtpRepositoryProtocol", "OtpRepository"]

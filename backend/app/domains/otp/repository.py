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
from datetime import date
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.location.models import Location

from .constants import OtpChannel
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

    async def get_daily_sms_consumption(
        self,
        *,
        organization_id: uuid.UUID | None,
        start_date: date,
        end_date: date,
    ) -> list[tuple[date, uuid.UUID, str, int]]: ...


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

    async def get_daily_sms_consumption(
        self,
        *,
        organization_id: uuid.UUID | None,
        start_date: date,
        end_date: date,
    ) -> list[tuple[date, uuid.UUID, str, int]]:
        """Count created SMS OTP requests by each location's local day.

        ``otp_requests`` is the authoritative record available in every
        deployment. It records an issued code, not carrier acceptance or
        handset delivery, so this query intentionally makes no such claim.
        Locations without requests have no row rather than invented zeroes.
        """
        usage_date = func.date(
            func.timezone(Location.timezone, OtpRequest.created_at)
        ).label("usage_date")
        clauses: list[object] = [
            OtpRequest.is_deleted.is_(False),
            Location.is_deleted.is_(False),
            OtpRequest.channel == OtpChannel.SMS.value,
            usage_date >= start_date,
            usage_date <= end_date,
        ]
        if organization_id is not None:
            clauses.append(OtpRequest.organization_id == organization_id)

        statement = (
            select(
                usage_date,
                OtpRequest.location_id,
                Location.name,
                func.count(OtpRequest.id).label("sms_otp_requests"),
            )
            .join(Location, Location.id == OtpRequest.location_id)
            .where(*clauses)
            .group_by(usage_date, OtpRequest.location_id, Location.name)
            .order_by(usage_date.asc(), Location.name.asc())
        )
        result = await self.session.execute(statement)
        return [
            (row[0], row[1], row[2], int(row[3]))
            for row in result.all()
        ]


__all__ = ["OtpRepositoryProtocol", "OtpRepository"]

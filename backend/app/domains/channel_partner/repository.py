"""Data access layer for the Channel Partner domain.

Mirrors ``app.domains.quotation.repository.QuotationRepositoryProtocol``/
``QuotationRepository``'s shape: a ``Protocol`` describing the operations
the service layer needs, and a concrete, ``GenericRepository``-backed
implementation. Like ``QuotationRepository``, there is no
``organization_id``-scoped filtering here -- a channel partner belongs to
no organization (see ``models.py``'s own module docstring).

``create_partner`` deliberately lets ``app.database.exceptions
.DuplicateRecordError`` (raised by ``GenericRepository._flush_or_raise`` on
the ``gst_number`` unique-constraint violation) propagate unhandled --
``service.py`` is the layer that translates it into the domain-specific
``DuplicateGstNumberError``, the same "repository stays a thin DB-error-
agnostic layer, service translates" split every other domain in this
codebase already draws.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import ChannelPartner


class ChannelPartnerRepositoryProtocol(Protocol):
    async def create_partner(self, **fields: object) -> ChannelPartner: ...

    async def get_by_id(
        self, channel_partner_id: uuid.UUID
    ) -> ChannelPartner | None: ...

    async def update_partner(
        self, partner: ChannelPartner, data: dict[str, object]
    ) -> ChannelPartner: ...

    async def list_partners(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[ChannelPartner], PaginationMeta]: ...


class ChannelPartnerRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ChannelPartnerRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.partners = GenericRepository(ChannelPartner, session)

    async def create_partner(self, **fields: object) -> ChannelPartner:
        return await self.partners.create(fields)

    async def get_by_id(self, channel_partner_id: uuid.UUID) -> ChannelPartner | None:
        return await self.partners.get_by_id(channel_partner_id)

    async def update_partner(
        self, partner: ChannelPartner, data: dict[str, object]
    ) -> ChannelPartner:
        return await self.partners.update(partner, data)

    def _list_filters(self, *, status: str | None, search: str | None) -> list:
        filters = [ChannelPartner.is_deleted.is_(False)]
        if status is not None:
            filters.append(ChannelPartner.status == status)
        if search is not None:
            like = f"%{search}%"
            filters.append(
                or_(
                    ChannelPartner.name.ilike(like),
                    ChannelPartner.phone.ilike(like),
                    ChannelPartner.email.ilike(like),
                    ChannelPartner.city.ilike(like),
                    ChannelPartner.gst_number.ilike(like),
                )
            )
        return filters

    async def list_partners(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[ChannelPartner], PaginationMeta]:
        filters = self._list_filters(status=status, search=search)

        count_statement = (
            select(func.count()).select_from(ChannelPartner).where(*filters)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(ChannelPartner)
            .where(*filters)
            .order_by(ChannelPartner.created_at.desc())
        )
        params = PageParams(page=page, page_size=page_size)
        result = await self.session.execute(paginate(statement, params))
        items = list(result.scalars().all())
        return items, PaginationMeta.from_total(params, total_items)


__all__ = ["ChannelPartnerRepositoryProtocol", "ChannelPartnerRepository"]

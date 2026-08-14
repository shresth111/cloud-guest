"""Data access layer for the Quotation domain.

Mirrors ``app.domains.billing.repository.InvoiceRepositoryProtocol``/
``InvoiceRepository``'s shape: a ``Protocol`` describing the operations the
service layer needs, and a concrete, ``GenericRepository``-backed
implementation. Like ``DemoRequestRepository``, there is no
``organization_id``-scoped filtering here -- a quotation belongs to no
organization (see ``models.py``'s own module docstring).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import Quotation, QuotationLineItem


class QuotationRepositoryProtocol(Protocol):
    async def create_quotation(self, **fields: object) -> Quotation: ...

    async def create_line_item(self, **fields: object) -> QuotationLineItem: ...

    async def get_by_id(self, quotation_id: uuid.UUID) -> Quotation | None: ...

    async def list_items(self, quotation_id: uuid.UUID) -> list[QuotationLineItem]: ...

    async def update_quotation(
        self, quotation: Quotation, data: dict[str, object]
    ) -> Quotation: ...

    async def list_quotations(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[Quotation], PaginationMeta]: ...


class QuotationRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``QuotationRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.quotations = GenericRepository(Quotation, session)
        self.line_items = GenericRepository(QuotationLineItem, session)

    async def create_quotation(self, **fields: object) -> Quotation:
        return await self.quotations.create(fields)

    async def create_line_item(self, **fields: object) -> QuotationLineItem:
        return await self.line_items.create(fields)

    async def get_by_id(self, quotation_id: uuid.UUID) -> Quotation | None:
        return await self.quotations.get_by_id(quotation_id)

    async def list_items(self, quotation_id: uuid.UUID) -> list[QuotationLineItem]:
        return await self.line_items.get_all(
            filters={"quotation_id": quotation_id},
            sort_by="created_at",
            sort_order=SortOrder.ASC,
        )

    async def update_quotation(
        self, quotation: Quotation, data: dict[str, object]
    ) -> Quotation:
        return await self.quotations.update(quotation, data)

    def _list_filters(self, *, status: str | None, search: str | None) -> list:
        filters = [Quotation.is_deleted.is_(False)]
        if status is not None:
            filters.append(Quotation.status == status)
        if search is not None:
            like = f"%{search}%"
            filters.append(
                or_(
                    Quotation.client_name.ilike(like),
                    Quotation.client_email.ilike(like),
                    Quotation.client_company_name.ilike(like),
                    Quotation.quotation_number.ilike(like),
                )
            )
        return filters

    async def list_quotations(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[Quotation], PaginationMeta]:
        filters = self._list_filters(status=status, search=search)

        count_statement = select(func.count()).select_from(Quotation).where(*filters)
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(Quotation).where(*filters).order_by(Quotation.created_at.desc())
        )
        params = PageParams(page=page, page_size=page_size)
        result = await self.session.execute(paginate(statement, params))
        items = list(result.scalars().all())
        return items, PaginationMeta.from_total(params, total_items)


__all__ = ["QuotationRepositoryProtocol", "QuotationRepository"]

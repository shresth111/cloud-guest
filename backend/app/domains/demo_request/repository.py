"""Data access layer for the Demo Request domain.

Mirrors ``app.domains.support_tickets.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``DemoRequestRepositoryProtocol``), and a concrete, ``GenericRepository``-
backed implementation (``DemoRequestRepository``). Unlike Support Tickets,
there is no ``users`` join to resolve here -- a demo request has no
``created_by_user_id``/``assigned_to_user_id`` at all (see ``models.py``'s
own module docstring), so this is a thinner wrapper than
``TicketRepository``.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import DemoRequest


class DemoRequestRepositoryProtocol(Protocol):
    async def create(self, **fields: object) -> DemoRequest: ...

    async def get_by_id(self, demo_request_id: uuid.UUID) -> DemoRequest | None: ...

    async def update(
        self, demo_request: DemoRequest, data: dict[str, object]
    ) -> DemoRequest: ...

    async def list_records(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
        property_type: str | None = None,
    ) -> tuple[list[DemoRequest], PaginationMeta]: ...


class DemoRequestRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``DemoRequestRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.demo_requests = GenericRepository(DemoRequest, session)

    async def create(self, **fields: object) -> DemoRequest:
        return await self.demo_requests.create(fields)

    async def get_by_id(self, demo_request_id: uuid.UUID) -> DemoRequest | None:
        return await self.demo_requests.get_by_id(demo_request_id)

    async def update(
        self, demo_request: DemoRequest, data: dict[str, object]
    ) -> DemoRequest:
        return await self.demo_requests.update(demo_request, data)

    def _list_filters(
        self,
        *,
        status: str | None,
        search: str | None,
        property_type: str | None = None,
    ) -> list:
        filters = [DemoRequest.is_deleted.is_(False)]
        if status is not None:
            filters.append(DemoRequest.status == status)
        if property_type is not None:
            filters.append(DemoRequest.property_type == property_type)
        if search is not None:
            like = f"%{search}%"
            filters.append(
                or_(
                    DemoRequest.full_name.ilike(like),
                    DemoRequest.email.ilike(like),
                    DemoRequest.company_name.ilike(like),
                )
            )
        return filters

    async def list_records(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
        property_type: str | None = None,
    ) -> tuple[list[DemoRequest], PaginationMeta]:
        filters = self._list_filters(
            status=status, search=search, property_type=property_type
        )

        count_statement = select(func.count()).select_from(DemoRequest).where(*filters)
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(DemoRequest).where(*filters).order_by(DemoRequest.created_at.desc())
        )
        params = PageParams(page=page, page_size=page_size)
        result = await self.session.execute(paginate(statement, params))
        items = list(result.scalars().all())
        return items, PaginationMeta.from_total(params, total_items)


__all__ = ["DemoRequestRepositoryProtocol", "DemoRequestRepository"]

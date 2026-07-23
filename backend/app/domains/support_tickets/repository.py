"""Data access layer for the Support Tickets domain.

Mirrors ``app.domains.guest_access.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``TicketRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``TicketRepository``) wrapping one ``GenericRepository``
instance, plus hand-written ``select`` statements for the one thing
``GenericRepository`` genuinely can't express: joining ``users`` (once for
``created_by_user_id``, once more, aliased, for ``assigned_to_user_id``) so
``TicketResponse.created_by_name``/``created_by_email``/``assigned_to_name``
never require the frontend to resolve names separately with a second round
trip per ticket.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate
from app.domains.auth.models import User

from .models import SupportTicket


def _display_name(user: User) -> str:
    return f"{user.first_name} {user.last_name}".strip()


@dataclass(frozen=True, slots=True)
class TicketRecord:
    """A ``SupportTicket`` row plus the requester/assignee display name and
    email joined in from ``users`` -- see module docstring for why the
    repository resolves these rather than pushing a second round trip onto
    the caller."""

    ticket: SupportTicket
    created_by_name: str
    created_by_email: str
    assigned_to_name: str | None


class TicketRepositoryProtocol(Protocol):
    async def create(self, **fields: object) -> SupportTicket: ...

    async def get_by_id(self, ticket_id: uuid.UUID) -> SupportTicket | None: ...

    async def get_record_by_id(self, ticket_id: uuid.UUID) -> TicketRecord | None: ...

    async def update(
        self, ticket: SupportTicket, data: dict[str, object]
    ) -> SupportTicket: ...

    async def list_records(
        self,
        *,
        organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
        status: str | None = None,
        priority: str | None = None,
        search: str | None = None,
    ) -> tuple[list[TicketRecord], PaginationMeta]: ...


class TicketRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``TicketRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.tickets = GenericRepository(SupportTicket, session)

    async def create(self, **fields: object) -> SupportTicket:
        return await self.tickets.create(fields)

    async def get_by_id(self, ticket_id: uuid.UUID) -> SupportTicket | None:
        return await self.tickets.get_by_id(ticket_id)

    async def update(
        self, ticket: SupportTicket, data: dict[str, object]
    ) -> SupportTicket:
        return await self.tickets.update(ticket, data)

    def _to_record(
        self, ticket: SupportTicket, creator: User, assignee: User | None
    ) -> TicketRecord:
        return TicketRecord(
            ticket=ticket,
            created_by_name=_display_name(creator),
            created_by_email=creator.email,
            assigned_to_name=_display_name(assignee) if assignee is not None else None,
        )

    async def get_record_by_id(self, ticket_id: uuid.UUID) -> TicketRecord | None:
        assignee = aliased(User)
        statement = (
            select(SupportTicket, User, assignee)
            .join(User, User.id == SupportTicket.created_by_user_id)
            .outerjoin(assignee, assignee.id == SupportTicket.assigned_to_user_id)
            .where(
                SupportTicket.id == ticket_id, SupportTicket.is_deleted.is_(False)
            )
        )
        result = await self.session.execute(statement)
        row = result.first()
        if row is None:
            return None
        ticket, creator, assigned = row
        return self._to_record(ticket, creator, assigned)

    def _list_filters(
        self,
        *,
        organization_id: uuid.UUID | None,
        status: str | None,
        priority: str | None,
        search: str | None,
    ) -> list:
        filters = [SupportTicket.is_deleted.is_(False)]
        # organization_id is None only for a platform-level caller with no
        # X-Organization-Id context -- the Master dashboard "every
        # organization's tickets" cross-tenant view (see
        # app.domains.support_tickets.router's own module docstring). An
        # org-scoped caller always has a concrete organization_id here.
        if organization_id is not None:
            filters.append(SupportTicket.organization_id == organization_id)
        if status is not None:
            filters.append(SupportTicket.status == status)
        if priority is not None:
            filters.append(SupportTicket.priority == priority)
        if search is not None:
            like = f"%{search}%"
            filters.append(
                or_(
                    SupportTicket.subject.ilike(like),
                    SupportTicket.description.ilike(like),
                )
            )
        return filters

    async def list_records(
        self,
        *,
        organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
        status: str | None = None,
        priority: str | None = None,
        search: str | None = None,
    ) -> tuple[list[TicketRecord], PaginationMeta]:
        filters = self._list_filters(
            organization_id=organization_id,
            status=status,
            priority=priority,
            search=search,
        )

        count_statement = (
            select(func.count()).select_from(SupportTicket).where(*filters)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        assignee = aliased(User)
        statement = (
            select(SupportTicket, User, assignee)
            .join(User, User.id == SupportTicket.created_by_user_id)
            .outerjoin(assignee, assignee.id == SupportTicket.assigned_to_user_id)
            .where(*filters)
            .order_by(SupportTicket.created_at.desc())
        )
        params = PageParams(page=page, page_size=page_size)
        result = await self.session.execute(paginate(statement, params))
        records = [self._to_record(t, c, a) for t, c, a in result.all()]
        return records, PaginationMeta.from_total(params, total_items)


__all__ = ["TicketRepositoryProtocol", "TicketRepository", "TicketRecord"]

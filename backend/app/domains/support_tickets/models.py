"""SQLAlchemy ORM model for the Support Tickets domain.

:class:`SupportTicket` -- a customer (org member) support ticket, raised
from an organization's own dashboard and visible to platform admins across
every organization on the Master dashboard.

:class:`SupportTicketReply` -- the ticket's reply thread (customer <->
platform support), added in the real-time pass (see ``router.py``'s
WebSocket section). A separate child table, not a JSON blob on
``SupportTicket`` itself, so each reply gets its own author/timestamp and
can be paginated/streamed independently of the parent ticket row.

``organization_id`` is required (every ticket belongs to exactly one
organization); ``location_id`` is nullable, following the exact same
convention ``app.domains.guest_access.models.GuestAccessRule.location_id``
already established: ``NULL`` means an org-wide ticket, not about one
specific location.

``category`` is a plain, unvalidated ``String(50)`` -- no DB enum type,
mirroring how ``GuestAccessRule.rule_type`` is a plain ``String`` rather
than a native PostgreSQL enum (adding a new category never requires an
``ALTER TYPE`` migration). ``priority``/``status`` are likewise plain
``String`` columns, validated only at the application/schema layer (see
``constants.py``) for the identical reason.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version) for the same reason every other domain does --
``GenericRepository``/Alembic autogenerate/cross-domain FKs all keep
working uniformly.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import TicketPriority, TicketStatus


class SupportTicketReply(BaseModel):
    """One message in a ticket's reply thread -- either the customer (org
    member who raised/owns the ticket) or platform support staff.

    ``is_staff_reply`` is set once at creation time from the same
    "organization context present or absent" signal
    ``TicketService.list_tickets``/``router.py`` already use to distinguish
    the customer dashboard view from the Master (platform) dashboard view
    (see ``service.TicketService.add_reply``): a reply created with an
    ``X-Organization-Id`` context is the ticket owner's own organization
    replying; a reply created with no organization context is a platform
    support agent replying from the Master console. No separate "author
    role" lookup is needed for this -- the same signal the rest of this
    domain already trusts.

    Extends ``app.database.base.BaseModel`` for the same reason
    ``SupportTicket`` does -- see that model's own docstring."""

    __tablename__ = "support_ticket_replies"

    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("support_tickets.id", ondelete="CASCADE"),
        nullable=False,
    )
    author_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_staff_reply: Mapped[bool] = mapped_column(nullable=False, default=False)

    __table_args__ = (
        Index("ix_support_ticket_replies_ticket_id", "ticket_id"),
        Index("ix_support_ticket_replies_author_user_id", "author_user_id"),
    )

    def __repr__(self) -> str:
        return f"<SupportTicketReply(id={self.id}, ticket_id={self.ticket_id})>"


class SupportTicket(BaseModel):
    """A support ticket raised by an organization member, resolvable by a
    platform admin."""

    __tablename__ = "support_tickets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NULL == organization-wide ticket, not about one specific location --
    # mirrors app.domains.guest_access.models.GuestAccessRule.location_id's
    # identical "NULL means org-wide" convention.
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ON DELETE SET NULL, not CASCADE (unlike created_by_user_id): a ticket
    # must survive its assignee's own account being deleted -- it simply
    # becomes unassigned again, whereas a ticket has no meaning at all
    # without its creator.
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Free-form, application-level only -- see module docstring.
    category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TicketPriority.MEDIUM.value
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TicketStatus.OPEN.value
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Application-set, not a DB trigger -- see
    # service.TicketService.update_ticket for the auto-set/auto-clear logic
    # on status transitions into/out of RESOLVED_STATUSES.
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_support_tickets_organization_id", "organization_id"),
        Index("ix_support_tickets_location_id", "location_id"),
        Index("ix_support_tickets_created_by_user_id", "created_by_user_id"),
        Index("ix_support_tickets_assigned_to_user_id", "assigned_to_user_id"),
        Index("ix_support_tickets_status", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<SupportTicket(id={self.id}, subject={self.subject!r}, "
            f"status={self.status})>"
        )


__all__ = ["SupportTicket", "SupportTicketReply"]

"""SQLAlchemy ORM model for the Demo Request domain.

:class:`DemoRequest` -- a "Book a Demo" lead submitted by a prospective
customer through a public, unauthenticated marketing form (see
``router.py``'s module docstring). Unlike every tenant-scoped domain in this
codebase (``SupportTicket``, ``GuestAccessRule``, ...), this row has no
``organization_id``/``created_by_user_id`` at all -- the submitter is, by
definition, not yet a platform user or member of any organization. This is
the same "no platform identity exists yet" shape ``app.domains.otp.models
.OtpRequest`` already establishes for its own guest-facing rows.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version) for the same reason every other domain does --
``GenericRepository``/Alembic autogenerate all keep working uniformly. No
separate ``submitted_at`` column: ``BaseModel.created_at`` already records
the moment the row was inserted, i.e. the moment the request was submitted
-- ``schemas.DemoRequestResponse`` exposes it under the ``submitted_at``
name for a clearer public-facing/Master-console contract, without storing
the same timestamp twice.
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DemoRequestStatus


class DemoRequest(BaseModel):
    """A "Book a Demo" lead-capture submission, visible/manageable on the
    Master console."""

    __tablename__ = "demo_requests"

    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(30), nullable=True)
    company_name: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=DemoRequestStatus.NEW.value
    )
    # Free-form, application-set only (e.g. "followed up 2026-07-25, no
    # answer") -- mirrors SupportTicket.resolution_notes's identical
    # "internal-team scratch pad, not shown to the submitter" shape.
    internal_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # The field the Master console filters/searches its queue by most
        # often -- same reasoning as SupportTicket's own
        # ix_support_tickets_status index.
        Index("ix_demo_requests_status", "status"),
        Index("ix_demo_requests_email", "email"),
    )

    def __repr__(self) -> str:
        return (
            f"<DemoRequest(id={self.id}, email={self.email!r}, "
            f"status={self.status})>"
        )


__all__ = ["DemoRequest"]

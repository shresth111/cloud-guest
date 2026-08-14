"""SQLAlchemy ORM models for the Quotation domain.

:class:`Quotation` -- a branded PDF price quotation a Master console
operator generates and emails to a prospective or existing client.
Deliberately mirrors ``app.domains.billing.models.Invoice``/``InvoiceItem``'s
shape (line items as a real child table, ``Numeric`` money columns, amounts
computed once at creation and stored -- never recomputed on read) for the
same reasons that domain documents, while carrying **no** ``organization_id``
at all -- like ``app.domains.demo_request.models.DemoRequest``, a quotation
recipient is very often a prospect who is not a platform user or member of
any organization yet. An operator quoting an *existing* client simply types
that client's name/email/company again; this domain does not require (or
attempt to enforce) a link to a real ``Organization`` row.

No FK to ``app.domains.billing.models.Plan``: a line item is always a flat
``description``/``quantity``/``unit_price`` row, the same shape
``InvoiceItem`` already uses. The Master console UI may let an operator
pre-fill those fields from an existing ``Plan`` (via the already-public
``GET /billing/plans`` listing) as a client-side convenience, but nothing is
persisted linking a ``QuotationLineItem`` back to the ``Plan`` it was
copied from -- keeps this domain decoupled from billing internals, the same
posture ``InvoiceItem`` itself already takes (it carries no ``plan_id``
either).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import BaseModel

from .constants import QuotationStatus


class Quotation(BaseModel):
    """One generated, emailed (or attempted) price quotation."""

    __tablename__ = "quotations"

    quotation_number: Mapped[str] = mapped_column(
        String(50), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=QuotationStatus.DRAFT.value
    )

    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    client_email: Mapped[str] = mapped_column(String(255), nullable=False)
    # The client's own company/property name -- e.g. the hotel/venue being
    # quoted, may differ from client_name (the contact person).
    client_company_name: Mapped[str] = mapped_column(String(255), nullable=False)

    subtotal: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    tax_percentage: Mapped[Decimal] = mapped_column(
        Numeric(5, 2), default=Decimal("0"), nullable=False
    )
    tax_amount: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), default=Decimal("0"), nullable=False
    )
    total_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="USD", nullable=False)

    valid_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Delivery outcome -- mirrors app.domains.billing.router's own
    # "a failed/unconfigured email send is never a rollback of the
    # already-created document" posture: the quotation row always exists
    # once generated; these three columns record what happened when this
    # module tried to email it.
    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    email_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    items: Mapped[list[QuotationLineItem]] = relationship(
        "QuotationLineItem",
        back_populates="quotation",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_quotations_status", "status"),
        Index("ix_quotations_client_email", "client_email"),
        Index("ix_quotations_quotation_number", "quotation_number", unique=True),
    )

    def __repr__(self) -> str:
        return (
            f"<Quotation(id={self.id}, quotation_number={self.quotation_number}, "
            f"status={self.status})>"
        )


class QuotationLineItem(BaseModel):
    """One line item on a :class:`Quotation`. Same ``quantity``-as-``Numeric``
    and "compute once, store the result" ``amount`` discipline as
    ``app.domains.billing.models.InvoiceItem`` -- see that model's own
    docstring for the full reasoning."""

    __tablename__ = "quotation_line_items"

    quotation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("quotations.id", ondelete="CASCADE"),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), default=Decimal("1"), nullable=False
    )
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    quotation: Mapped[Quotation] = relationship("Quotation", back_populates="items")

    __table_args__ = (Index("ix_quotation_line_items_quotation_id", "quotation_id"),)

    def __repr__(self) -> str:
        return (
            f"<QuotationLineItem(quotation_id={self.quotation_id}, "
            f"amount={self.amount})>"
        )


__all__ = ["Quotation", "QuotationLineItem"]

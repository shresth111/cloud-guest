"""SQLAlchemy models for the Invoice domain."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Numeric, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class Invoice(BaseModel):
    """Represents a financial billing invoice for an organization."""

    __tablename__ = "invoices"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=True
    )

    invoice_number: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="draft", nullable=False)  # draft, open, paid, void

    issue_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    due_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    subtotal: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False, default=0.00)
    tax_amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False, default=0.00)
    tax_rate: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False, default=0.1800)  # default 18% GST
    discount_amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False, default=0.00)
    total: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False, default=0.00)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")

    pdf_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    
    # Store dynamic metadata such as line items, company tax addresses, PDF layout choices
    invoice_metadata: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class CreditNote(BaseModel):
    """Represents adjustments, refunds, or credit entries linked to an invoice."""

    __tablename__ = "credit_notes"

    invoice_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("invoices.id"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )

    amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="applied", nullable=False)

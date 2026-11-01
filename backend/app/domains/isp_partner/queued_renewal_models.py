"""QUEUED-RENEWAL: a renewal paid (or billed) now whose plan starts when the
current one ends. Own table only. The invoice, the validity extension and the
JAZE-1 "renewed" timeline event are made by the existing renew/recharge code;
this row remembers which plan to switch to, and when."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["QUEUED_RENEWAL_TABLES", "IspQueuedRenewal"]


class IspQueuedRenewal(BaseModel):
    """Status: pending (waiting for ``starts_at``) | active (the plan was
    switched) | cancelled (credit note through JAZE-1 revert)."""

    __tablename__ = "isp_queued_renewals"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    customer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    subscriber_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_packages.id"), nullable=False
    )
    speed_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_speed_groups.id"), nullable=False
    )
    #: the plan running while it waits (shown, and restored on cancel)
    previous_package_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_packages.id"), nullable=True
    )
    cycles: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    invoice_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_invoices.id"), nullable=True
    )
    #: the JAZE-1 ``renewed`` event (its detail drives revert = cancel)
    renewal_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancel_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: {"credit_note_number": ..., "voided_receipts": [...]}
    outcome: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index(
            "uq_isp_queued_renewals_key",
            "isp_organization_id",
            "idempotency_key",
            unique=True,
        ),
        Index(
            "uq_isp_queued_renewals_pending",
            "subscriber_id",
            unique=True,
            postgresql_where=text("status = 'pending' AND deleted_at IS NULL"),
        ),
        Index("ix_isp_queued_renewals_due", "status", "starts_at"),
    )


QUEUED_RENEWAL_TABLES = ("isp_queued_renewals",)

"""COLLECTIONS-1: promise-to-pay, collection notes/timeline and the
end-of-day cash handover. Own tables only; invoices and payments are the
existing ``isp_invoices`` / ``isp_payments`` rows, never altered.

A *party* is the one who owes: a subscriber (``subscriber_id`` set) or a
customer billed directly (``subscriber_id`` NULL). ``customer_organization_id``
is always set, so every row is scoped through the usual customer confinement.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import BigInteger, Date, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "COLLECTIONS_TABLES",
    "IspCashHandover",
    "IspCashHandoverItem",
    "IspCollectionEvent",
    "IspCollectionPromise",
]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None) -> Any:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspCollectionPromise(BaseModel):
    """A promise to pay by ``promised_on``. ``target_paise`` is what has to
    arrive (the promised amount, else the overdue balance when it was made).
    Status: open | kept | broken | cancelled | superseded. A new promise for
    the same party supersedes the open one."""

    __tablename__ = "isp_collection_promises"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    subscriber_id: Mapped[uuid.UUID | None] = _fk(
        "isp_subscribers.id", nullable=True, ondelete="CASCADE"
    )
    promised_on: Mapped[date] = mapped_column(Date, nullable=False)
    amount_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    target_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    overdue_at_creation_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: JAZE-5 field task raised when the promise was missed (Apps on only)
    followup_task_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index(
            "ix_isp_collection_promises_isp_status",
            "isp_organization_id",
            "status",
            "promised_on",
        ),
        Index(
            "ix_isp_collection_promises_party",
            "customer_organization_id",
            "subscriber_id",
        ),
    )


class IspCollectionEvent(BaseModel):
    """One collections timeline line: a note (with an optional call outcome),
    a promise made/kept/broken/cancelled, cash collected, a handover step."""

    __tablename__ = "isp_collection_events"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    subscriber_id: Mapped[uuid.UUID | None] = _fk(
        "isp_subscribers.id", nullable=True, ondelete="CASCADE"
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    promise_id: Mapped[uuid.UUID | None] = _fk(
        "isp_collection_promises.id", nullable=True, ondelete="SET NULL"
    )
    payment_id: Mapped[uuid.UUID | None] = _fk("isp_payments.id", nullable=True)
    detail: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index(
            "ix_isp_collection_events_party",
            "customer_organization_id",
            "subscriber_id",
            "occurred_at",
        ),
        Index("ix_isp_collection_events_isp", "isp_organization_id", "occurred_at"),
    )


class IspCashHandover(BaseModel):
    """A collector's end-of-day cash handover. ``expected_paise`` is the sum
    of the confirmed cash payments in it when submitted; ``declared_paise`` is
    what the collector says they hand over; ``received_paise`` is what the
    approver counted. Status: submitted | approved | rejected."""

    __tablename__ = "isp_cash_handovers"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    collector_user_id: Mapped[uuid.UUID] = _fk("users.id")
    business_date: Mapped[date] = mapped_column(Date, nullable=False)
    expected_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    declared_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    received_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    decided_by: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index(
            "ix_isp_cash_handovers_isp",
            "isp_organization_id",
            "status",
            "business_date",
        ),
        Index("ix_isp_cash_handovers_collector", "collector_user_id", "business_date"),
    )


class IspCashHandoverItem(BaseModel):
    """One cash payment inside a handover. A payment sits in at most one live
    handover (partial unique index); a rejected handover's items are
    soft-deleted so the payments can be handed over again."""

    __tablename__ = "isp_cash_handover_items"

    handover_id: Mapped[uuid.UUID] = _fk("isp_cash_handovers.id", ondelete="CASCADE")
    payment_id: Mapped[uuid.UUID] = _fk("isp_payments.id")
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (
        Index(
            "uq_isp_cash_handover_items_payment",
            "payment_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_isp_cash_handover_items_handover", "handover_id"),
    )


COLLECTIONS_TABLES = (
    "isp_collection_promises",
    "isp_collection_events",
    "isp_cash_handovers",
    "isp_cash_handover_items",
)

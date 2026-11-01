"""REFERRAL-1: subscriber A referred subscriber B; once B's first invoice is
paid, A gets a credit on A's next invoice. Own tables only. The credit itself
is an ordinary credit note issued by ``IspBillingService.credit_note`` (the
existing credit path), never a payment or a new kind of money row."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["REFERRAL_TABLES", "IspReferral", "IspReferralSettings"]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspReferralSettings(BaseModel):
    """Per-ISP rules. ``reward_paise`` is the credit (GST inclusive, split like
    any credit note). ``max_rewards_per_year``: rewards one referrer may earn
    in any 365 days. ``window_days``: B must be referred within this many
    days of being created. ``min_first_invoice_paise``: B's first invoice
    must be at least this much."""

    __tablename__ = "isp_referral_settings"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    reward_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    max_rewards_per_year: Mapped[int] = mapped_column(
        Integer, nullable=False, default=12
    )
    window_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    min_first_invoice_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )

    __table_args__ = (
        Index(
            "uq_isp_referral_settings_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspReferral(BaseModel):
    """Status: pending (B's first invoice not paid yet) -> earned (reward
    fixed) -> applied (credit note on A's invoice) | rejected (a rule said no)
    | cancelled (by staff, pending only)."""

    __tablename__ = "isp_referrals"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    referrer_subscriber_id: Mapped[uuid.UUID] = _fk(
        "isp_subscribers.id", ondelete="CASCADE"
    )
    referred_subscriber_id: Mapped[uuid.UUID] = _fk(
        "isp_subscribers.id", ondelete="CASCADE"
    )
    referrer_customer_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    referred_customer_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    reward_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    qualifying_invoice_id: Mapped[uuid.UUID | None] = _fk(
        "isp_invoices.id", nullable=True
    )
    earned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    applied_invoice_id: Mapped[uuid.UUID | None] = _fk("isp_invoices.id", nullable=True)
    credit_note_id: Mapped[uuid.UUID | None] = _fk("isp_invoices.id", nullable=True)
    applied_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    #: append-only [{at, status, by, detail}]
    history: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )

    __table_args__ = (
        # a subscriber can be referred once (cancelled/rejected rows aside)
        Index(
            "uq_isp_referrals_referred",
            "referred_subscriber_id",
            unique=True,
            postgresql_where=text(
                "status IN ('pending', 'earned', 'applied') AND deleted_at IS NULL"
            ),
        ),
        Index("ix_isp_referrals_isp_status", "isp_organization_id", "status"),
        Index("ix_isp_referrals_referrer", "referrer_subscriber_id"),
    )


REFERRAL_TABLES = ("isp_referral_settings", "isp_referrals")

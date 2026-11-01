"""FRANCHISE-2 (ADDENDUM_06): zone revenue share, renewal auto-debit,
recurring zone charges and settlements. Own tables; JAZE-4's
``isp_zone_profiles`` / ``isp_zone_ledger_entries`` are written through
their normal row shape and never altered. Zones never get logins (D6)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
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

__all__ = [
    "FRANCHISE_TABLES",
    "IspZoneAutoDebit",
    "IspZoneCharge",
    "IspZoneSettlement",
    "IspZoneSharePlan",
]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None) -> Any:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspZoneSharePlan(BaseModel):
    """How the ISP's share of a zone's subscriber renewals is taken from the
    zone wallet. ``percent``: ISP share = invoice total x (1 - the zone's
    JAZE-4 ``revenue_share_bp``). ``wholesale``: a fixed amount per renewal
    invoice. A zone without a plan is never auto-debited."""

    __tablename__ = "isp_zone_share_plans"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id", ondelete="CASCADE")
    #: percent | wholesale
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    wholesale_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    auto_debit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    #: min-balance alert state (J14 Telegram), one alert per dip
    below_min_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    alerted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_zone_share_plans_zone",
            "zone_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspZoneAutoDebit(BaseModel):
    """One automatic ledger move for one document: ``debit`` for a renewal
    invoice, ``reversal`` for a credit note against it. Unique per
    (document, kind), so a retried request never debits twice."""

    __tablename__ = "isp_zone_autodebits"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")
    #: the invoice (debit) or the credit note (reversal)
    document_id: Mapped[uuid.UUID] = _fk("isp_invoices.id")
    #: for a reversal: the invoice it reverses
    invoice_id: Mapped[uuid.UUID] = _fk("isp_invoices.id")
    #: debit | reversal
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ledger_entry_id: Mapped[uuid.UUID | None] = _fk(
        "isp_zone_ledger_entries.id", nullable=True
    )
    mode: Mapped[str] = mapped_column(String(10), nullable=False)

    __table_args__ = (
        Index("uq_isp_zone_autodebits_doc", "document_id", "kind", unique=True),
        Index("ix_isp_zone_autodebits_zone", "zone_id", "created_at"),
    )


class IspZoneCharge(BaseModel):
    """A recurring monthly charge to a zone (rent, support fee, ...)."""

    __tablename__ = "isp_zone_charges"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id", ondelete="CASCADE")
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: 1..28: the day of the month it is charged
    day_of_month: Mapped[int] = mapped_column(Integer, nullable=False)
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    starts_on: Mapped[date] = mapped_column(Date, nullable=False)
    #: "YYYY-MM" of the last month charged (idempotency)
    last_period: Mapped[str | None] = mapped_column(String(7), nullable=True)

    __table_args__ = (Index("ix_isp_zone_charges_zone", "zone_id"),)


class IspZoneSettlement(BaseModel):
    """A numbered settlement for one zone and period: what the zone owes the
    ISP (its share of renewals + charges) against what it paid in."""

    __tablename__ = "isp_zone_settlements"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")
    number: Mapped[str] = mapped_column(String(24), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    fy: Mapped[str] = mapped_column(String(5), nullable=False)
    period_from: Mapped[date] = mapped_column(Date, nullable=False)
    period_to: Mapped[date] = mapped_column(Date, nullable=False)
    opening_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    debits_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    credits_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    closing_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: the ISP's share of renewals + charges in the period (what is billed)
    billed_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    taxable_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cgst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sgst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    igst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    lines: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index(
            "uq_isp_zone_settlements_number",
            "isp_organization_id",
            "number",
            unique=True,
        ),
        Index("ix_isp_zone_settlements_zone", "zone_id", "period_to"),
    )


FRANCHISE_TABLES = (
    "isp_zone_share_plans",
    "isp_zone_autodebits",
    "isp_zone_charges",
    "isp_zone_settlements",
)

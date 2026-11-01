"""SMALL-4 (REVENUE-HUB MRR history): one row per ISP per ISP-local day,
written by the daily ISP task. Whole-ISP numbers (no zone / package /
confinement), so the hub reads them only for an unfiltered, unconfined view."""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal

from sqlalchemy import BigInteger, Date, ForeignKey, Index, Integer, Numeric
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["IspRevenueSnapshot"]


class IspRevenueSnapshot(BaseModel):
    __tablename__ = "isp_revenue_snapshots"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)
    mrr_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    arpu_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    active: Mapped[int] = mapped_column(Integer, nullable=False)
    pending: Mapped[int] = mapped_column(Integer, nullable=False)
    expired: Mapped[int] = mapped_column(Integer, nullable=False)
    churned: Mapped[int] = mapped_column(Integer, nullable=False)
    unpriced: Mapped[int] = mapped_column(Integer, nullable=False)
    #: month to date, subscriber invoices issued this month (taxable)
    billed_month_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: month to date, paid on this month's subscriber invoices (GST incl.)
    collected_month_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: open subscriber dues (GST incl.)
    dues_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: net billed (GST incl., less credit notes) in the trailing 90 days
    sales_90d_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dso_days: Mapped[Decimal | None] = mapped_column(Numeric(8, 1), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_revenue_snapshots_isp_date",
            "isp_organization_id",
            "snapshot_date",
            unique=True,
        ),
    )

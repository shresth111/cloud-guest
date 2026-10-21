"""ISP partner tables (API_CONTRACT §2). New tables only; nothing existing is
altered and every foreign key lives here.

* :class:`IspPartnerProfile` -- marks an MSP organization as an ISP. Its
  existence (and ``status == "active"``) is what every ``/isp`` route checks.
* :class:`IspCustomerProfile` -- the ISP-side attributes of a child
  organization (account number, contact, address).
* :class:`IspStaffCustomerScope` -- customer confinement of one ISP staff
  user. No rows for a user means "all customers".
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class IspPartnerProfile(BaseModel):
    __tablename__ = "isp_partner_profiles"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    support_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    support_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    default_customer_plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id"), nullable=False
    )
    max_customers: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    suspended_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (Index("ix_isp_partner_profiles_status", "status"),)


class IspCustomerProfile(BaseModel):
    __tablename__ = "isp_customer_profiles"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    customer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        unique=True,
    )
    external_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contact_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    address_line1: Mapped[str | None] = mapped_column(String(255), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state_province: Mapped[str | None] = mapped_column(String(100), nullable=True)
    postal_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: ADDENDUM_03 §4: a reporting label only (migration 0173, our own table).
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_zones.id"), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_customer_profiles_isp_external_ref",
            "isp_organization_id",
            "external_ref",
            unique=True,
            postgresql_where=text("external_ref IS NOT NULL AND deleted_at IS NULL"),
        ),
        Index("ix_isp_customer_profiles_isp_organization_id", "isp_organization_id"),
    )


class IspStaffCustomerScope(BaseModel):
    __tablename__ = "isp_staff_customer_scopes"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    customer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    __table_args__ = (
        Index(
            "uq_isp_staff_customer_scopes_user_customer",
            "user_id",
            "customer_organization_id",
            unique=True,
        ),
        Index(
            "ix_isp_staff_customer_scopes_isp_user", "isp_organization_id", "user_id"
        ),
    )


# Registered on the same metadata via this module, which alembic/env.py
# already imports (E2), so 1b needs no further registration line.
from .billing_models import *  # noqa: E402,F403
from .billing_models import BILLING_TABLES  # noqa: E402,F401

__all__ = ["IspCustomerProfile", "IspPartnerProfile", "IspStaffCustomerScope"]

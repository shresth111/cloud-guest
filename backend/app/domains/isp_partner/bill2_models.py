"""BILL-2: per-zone invoice branding, keyed by ``zone_id``.

A new table, so ``isp_zones`` / ``isp_zone_profiles`` are not altered.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["IspZoneBranding"]


class IspZoneBranding(BaseModel):
    __tablename__ = "isp_zone_branding"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_zones.id"), nullable=False
    )
    #: "Billed through ..." on the zone's invoices; empty -> the zone name.
    invoice_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    bank_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    bank_account_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    bank_account_number: Mapped[str | None] = mapped_column(String(34), nullable=True)
    bank_ifsc: Mapped[str | None] = mapped_column(String(11), nullable=True)
    bank_branch: Mapped[str | None] = mapped_column(String(120), nullable=True)
    upi_vpa: Mapped[str | None] = mapped_column(String(100), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_zone_branding_zone",
            "zone_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_isp_zone_branding_isp", "isp_organization_id"),
    )

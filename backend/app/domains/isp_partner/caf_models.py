"""CAF-2 workbench tables (additive; nothing pre-existing is altered).

* ``isp_caf_extras`` -- the CAF fields JAZE-3's KYC record does not carry
  (applicant category beyond individual/organisation, father's/spouse's
  name for a lead that has no KYC yet, locality, district, plot no.), keyed
  by ``subscriber_id`` or, before conversion, by ``lead_id``. Converting a
  lead re-keys the same row onto the new subscriber (``lead_id`` is kept for
  the trail).
* ``isp_caf_profiles`` -- one row per ISP: the authorised signatory's name
  and designation and an optional stamp image (object storage key) printed
  in the signatory box.

ID numbers are never stored here: the CAF reads JAZE-3's masked value
(Aadhaar = last four digits only).
"""

from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["APPLICANT_CATEGORIES", "CAF_TABLES", "IspCafExtras", "IspCafProfile"]

APPLICANT_CATEGORIES = (
    "individual",
    "proprietor",
    "partnership",
    "pvt_ltd",
    "public_ltd",
    "other",
)


def _fk(target: str, *, nullable: bool = False):  # noqa: ANN202
    return mapped_column(UUID(as_uuid=True), ForeignKey(target), nullable=nullable)


class IspCafExtras(BaseModel):
    __tablename__ = "isp_caf_extras"
    __table_args__ = (
        CheckConstraint(
            "subscriber_id IS NOT NULL OR lead_id IS NOT NULL",
            name="ck_isp_caf_extras_subject",
        ),
        Index(
            "uq_isp_caf_extras_subscriber",
            "subscriber_id",
            unique=True,
            postgresql_where=text("subscriber_id IS NOT NULL AND is_deleted = false"),
        ),
        Index(
            "uq_isp_caf_extras_lead",
            "lead_id",
            unique=True,
            postgresql_where=text(
                "lead_id IS NOT NULL AND subscriber_id IS NULL AND is_deleted = false"
            ),
        ),
    )

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    lead_id: Mapped[uuid.UUID | None] = _fk("isp_leads.id", nullable=True)
    #: individual | proprietor | partnership | pvt_ltd | public_ltd | other
    applicant_category: Mapped[str] = mapped_column(
        String(20), nullable=False, default="individual"
    )
    applicant_category_other: Mapped[str | None] = mapped_column(
        String(60), nullable=True
    )
    father_or_spouse_name: Mapped[str | None] = mapped_column(
        String(200), nullable=True
    )
    plot_no: Mapped[str | None] = mapped_column(String(60), nullable=True)
    locality: Mapped[str | None] = mapped_column(String(120), nullable=True)
    district: Mapped[str | None] = mapped_column(String(100), nullable=True)


class IspCafProfile(BaseModel):
    __tablename__ = "isp_caf_profiles"
    __table_args__ = (
        Index(
            "uq_isp_caf_profiles_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    signatory_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    signatory_designation: Mapped[str | None] = mapped_column(
        String(120), nullable=True
    )
    stamp_storage_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    stamp_content_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    stamp_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)


CAF_TABLES = ("isp_caf_extras", "isp_caf_profiles")

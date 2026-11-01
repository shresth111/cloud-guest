"""JAZE-3 compliance tables (ADDENDUM_05: J6 CAF/KYC, J17 report schedules).

All new, keyed by ``isp_subscribers.id`` / the ISP org. Nothing here is read
by any non-ISP code path, and every route that writes them is behind
``ISP_PARTNER_ENABLED``.

Aadhaar rule (Aadhaar Act 2016 s.29 + UIDAI storage regulations): a full
Aadhaar number is **never stored**. ``id_number_masked`` keeps only the last
four digits for Aadhaar (``XXXX XXXX 1234``). Other ID types keep the number
the ISP typed, because DoT CAF audits need it and no such statutory bar
exists for them; the API still masks it on read for non-owner roles.
"""

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
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


def _fk(target: str, *, nullable: bool = False) -> Any:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete="CASCADE"), nullable=nullable
    )


class IspComplianceSettings(BaseModel):
    """One row per ISP: licence identity printed on the CAF, the CAF number
    series, the NAT-feed freshness threshold."""

    __tablename__ = "isp_compliance_settings"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    legal_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    licence_number: Mapped[str | None] = mapped_column(String(80), nullable=True)
    #: e.g. "UL-ISP Category B", free text as printed on the licence
    licence_category: Mapped[str | None] = mapped_column(String(80), nullable=True)
    registered_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    compliance_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    caf_prefix: Mapped[str] = mapped_column(
        String(10), nullable=False, default="CAF", server_default="CAF"
    )
    caf_next_seq: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    #: A router whose newest NAT translation is older than this is "stale".
    nat_feed_stale_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default="60"
    )
    #: TRAI PMR: >= this download speed counts as the gigabit report.
    gigabit_threshold_mbps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1000, server_default="1000"
    )
    #: Churned = expired for more than this many days.
    churn_after_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default="60"
    )

    __table_args__ = (
        Index(
            "uq_isp_compliance_settings_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspSubscriberKyc(BaseModel):
    """KYC + CAF record of one subscriber connection."""

    __tablename__ = "isp_subscriber_kyc"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: individual | organization
    applicant_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="individual", server_default="individual"
    )
    full_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    father_or_spouse_name: Mapped[str | None] = mapped_column(
        String(200), nullable=True
    )
    #: male | female | other | undisclosed
    gender: Mapped[str | None] = mapped_column(String(12), nullable=True)
    date_of_birth: Mapped[date | None] = mapped_column(Date, nullable=True)
    nationality: Mapped[str | None] = mapped_column(
        String(40), nullable=True, default="Indian"
    )
    alternate_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    permanent_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    installation_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    installation_pincode: Mapped[str | None] = mapped_column(String(10), nullable=True)
    #: aadhaar | voter_id | passport | pan | driving_licence | ration_card | other
    id_proof_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: Aadhaar: "XXXX XXXX 1234" only. Never the full number.
    id_number_masked: Mapped[str | None] = mapped_column(String(40), nullable=True)
    id_number_last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    address_proof_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    address_proof_same_as_id: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    caf_number: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: auto | custom (a paper form's own number)
    caf_number_source: Mapped[str | None] = mapped_column(String(8), nullable=True)
    caf_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    installed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_subscriber_kyc_subscriber",
            "subscriber_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "uq_isp_subscriber_kyc_caf_number",
            "isp_organization_id",
            "caf_number",
            unique=True,
            postgresql_where=text("caf_number IS NOT NULL"),
        ),
        Index("ix_isp_subscriber_kyc_isp", "isp_organization_id"),
    )


class IspSubscriberDocument(BaseModel):
    """An uploaded KYC/installation file, stored in object storage."""

    __tablename__ = "isp_subscriber_documents"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id")
    #: photo | signature | id_proof | address_proof | caf_signed | install_report
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(400), nullable=False)
    filename: Mapped[str] = mapped_column(String(200), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        Index("ix_isp_subscriber_documents_sub", "subscriber_id", "kind"),
    )


class IspReportSchedule(BaseModel):
    """A monthly compliance-report email (J17). Runs only while
    ``ISP_COMPLIANCE_SCHEDULES_ENABLED`` is on."""

    __tablename__ = "isp_report_schedules"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: trai_pmr | agr | subscriber_status
    report_key: Mapped[str] = mapped_column(String(40), nullable=False)
    day_of_month: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    recipients: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    #: "YYYY-MM" of the last period sent: one email per period, never two.
    last_period_sent: Mapped[str | None] = mapped_column(String(7), nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_report_schedules_isp_key",
            "isp_organization_id",
            "report_key",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


COMPLIANCE_TABLES = (
    "isp_compliance_settings",
    "isp_subscriber_kyc",
    "isp_subscriber_documents",
    "isp_report_schedules",
)

__all__ = [
    "COMPLIANCE_TABLES",
    "IspComplianceSettings",
    "IspReportSchedule",
    "IspSubscriberDocument",
    "IspSubscriberKyc",
]

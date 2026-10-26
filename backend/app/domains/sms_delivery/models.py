"""``sms_delivery_logs`` -- one row per real SMS send attempt.

Plain ``Base`` + UUID, no soft-delete/audit/version: rows are written by send
sites and the DLR path only, never edited by a person, and deleted by the
retention sweep.

PII: the number is stored masked (``+91******3210``, the same shape
``app.domains.marketing.validators.mask_phone`` uses), never in full. The
message body is never stored -- an OTP body *is* the code.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, SmallInteger, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDMixin


class SmsDeliveryLog(UUIDMixin, Base):
    __tablename__ = "sms_delivery_logs"

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # The foreign keys (organizations CASCADE, locations SET NULL) live in
    # migration 0172 only, deliberately not on the ORM columns: an ORM-level
    # ForeignKey makes every flush resolve ``organizations``/``locations`` in
    # the shared metadata, so a process that had not imported those models
    # would fail the insert -- and the recorder swallows insert failures (it
    # must never break a send), so rows would silently go missing.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_source: Mapped[str] = mapped_column(
        String(8), nullable=False, server_default="wyfy"
    )
    recipient_masked: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The otp_requests / marketing_campaign_recipients / notification_deliveries
    # row this attempt belongs to. Deliberately no FK: the OTP request row is
    # rolled back when its send fails, and the failed attempt must survive.
    reference_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    provider_message_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    dlr_received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    dlr_source: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # The provider's own words for the last DLR answer we saw, truncated --
    # kept even when it was not a recognised status, so an unexpected answer
    # shape is visible instead of silently discarded.
    dlr_raw: Mapped[str | None] = mapped_column(String(120), nullable=True)
    dlr_poll_count: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="0"
    )
    last_dlr_poll_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_sms_delivery_logs_org_created", "organization_id", "created_at"),
        Index("ix_sms_delivery_logs_created_at", "created_at"),
        Index(
            "ix_sms_delivery_logs_provider_msg",
            "provider",
            "provider_message_id",
        ),
        Index(
            "ix_sms_delivery_logs_awaiting_dlr",
            "created_at",
            postgresql_where=text("status = 'sent'"),
        ),
    )


__all__ = ["SmsDeliveryLog"]

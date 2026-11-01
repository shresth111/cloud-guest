"""COMMS-2 (ADDENDUM_06): delivery receipts, the Meta webhook config, and the
per-event template library. Own tables; ``isp_message_log`` (JAZE-4) is read,
never altered: a receipt never rewrites the log row's ``status``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "COMMS_TABLES",
    "IspCommsWebhook",
    "IspMessageReceipt",
    "IspMessageTemplate",
]


def _org() -> Any:
    return mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )


class IspMessageReceipt(BaseModel):
    """One delivery status reported by Meta for one sent message."""

    __tablename__ = "isp_message_receipts"

    isp_organization_id: Mapped[uuid.UUID] = _org()
    message_log_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_message_log.id", ondelete="SET NULL"),
        nullable=True,
    )
    provider_message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: sent | delivered | read | failed (Meta's own words)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    #: Meta's timestamp for the status
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_title: Mapped[str | None] = mapped_column(String(300), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_message_receipts_msg_status",
            "isp_organization_id",
            "provider_message_id",
            "status",
            unique=True,
        ),
        Index("ix_isp_message_receipts_log", "message_log_id"),
    )


class IspCommsWebhook(BaseModel):
    """The ISP's Meta webhook: a secret path token, the verify token Meta
    echoes on subscribe, and the app secret that signs every POST."""

    __tablename__ = "isp_comms_webhooks"

    isp_organization_id: Mapped[uuid.UUID] = _org()
    path_token: Mapped[str] = mapped_column(String(64), nullable=False)
    verify_token: Mapped[str] = mapped_column(String(64), nullable=False)
    app_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rejected_count: Mapped[int] = mapped_column(
        nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        Index(
            "uq_isp_comms_webhooks_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("uq_isp_comms_webhooks_token", "path_token", unique=True),
    )


class IspMessageTemplate(BaseModel):
    """One event x channel template. WhatsApp: an approved Meta template
    (name + language, checked against the WABA). Email: subject + body with
    ``{{variable}}`` placeholders."""

    __tablename__ = "isp_message_templates"

    isp_organization_id: Mapped[uuid.UUID] = _org()
    event: Mapped[str] = mapped_column(String(24), nullable=False)
    #: email | whatsapp
    channel: Mapped[str] = mapped_column(String(10), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    email_subject: Mapped[str | None] = mapped_column(String(200), nullable=True)
    email_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    wa_template_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    wa_language: Mapped[str | None] = mapped_column(String(15), nullable=True)
    #: APPROVED / PENDING / REJECTED / ... as Meta reported it at last check
    wa_approval_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    wa_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    wa_body_params: Mapped[int | None] = mapped_column(nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index(
            "uq_isp_message_templates_event",
            "isp_organization_id",
            "event",
            "channel",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


COMMS_TABLES = ("isp_message_receipts", "isp_comms_webhooks", "isp_message_templates")

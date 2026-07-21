"""SQLAlchemy models for the notification domain: ``NotificationTemplate``
and ``NotificationDelivery``. See ``service.py``'s module docstring for the
full outbox/dispatch design."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class NotificationTemplate(BaseModel):
    """A reusable subject/body template for one ``(event_type, channel)``
    pair. ``organization_id IS NULL`` means a platform-wide default
    template, available to every tenant -- mirrors
    ``app.domains.router_provisioning.models.ConfigTemplate``'s identical
    nullable-FK-means-platform-wide convention. ``{{variable_name}}``
    placeholders are rendered via
    ``app.domains.router_provisioning.service.render_template`` (reused
    as-is -- see that domain's own module docstring; already reused
    cross-domain by ``app.domains.provisioning_engine``)."""

    __tablename__ = "notification_templates"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    subject_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_template: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_notification_templates_organization_id", "organization_id"),
        Index("ix_notification_templates_event_type", "event_type"),
        Index("ix_notification_templates_channel", "channel"),
        Index("ix_notification_templates_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<NotificationTemplate(event_type={self.event_type}, "
            f"channel={self.channel})>"
        )


class NotificationDelivery(BaseModel):
    """One durable outbox row: ``PENDING`` (written synchronously by
    ``NotificationService.enqueue``) -> ``SENT`` or ``RETRYING``/``FAILED``
    on a real send failure -- see ``service.py``'s module docstring for the
    full dispatch/retry contract. ``attachment_storage_key`` is an
    ``app.core.storage.ObjectStorageProtocol`` key (not the bytes
    themselves), so a voucher/invoice/report export can be attached
    without duplicating its content into this table.

    Note: this model deliberately does not use ``metadata`` as a column
    name -- that identifier is reserved by SQLAlchemy's declarative base
    (``Base.metadata``); free-form structured data lives in ``context``
    instead.
    """

    __tablename__ = "notification_deliveries"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    attachment_storage_key: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )
    attachment_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_notification_deliveries_organization_id", "organization_id"),
        Index("ix_notification_deliveries_status", "status"),
        Index("ix_notification_deliveries_event_type", "event_type"),
        Index("ix_notification_deliveries_next_attempt_at", "next_attempt_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<NotificationDelivery(event_type={self.event_type}, "
            f"status={self.status})>"
        )

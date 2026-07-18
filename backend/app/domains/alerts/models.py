"""SQLAlchemy ORM models for the Alerts domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, ForeignKey, String, Text, Boolean, Float
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

class Alert(BaseModel):
    """An alert triggered by monitoring rules or system failures."""

    __tablename__ = "alerts"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    alert_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), default="warning", nullable=False)
    category: Mapped[str] = mapped_column(String(50), default="router", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )


class AlertRule(BaseModel):
    """A rule defining threshold conditions for generating an Alert."""

    __tablename__ = "alert_rules"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    metric: Mapped[str] = mapped_column(String(100), nullable=False)
    condition: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., ">", "<", "=="
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    duration: Mapped[int] = mapped_column(default=60, nullable=False)  # duration in seconds

    severity: Mapped[str] = mapped_column(String(30), default="warning", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    channels: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False  # e.g., {"email": true, "slack": true}
    )

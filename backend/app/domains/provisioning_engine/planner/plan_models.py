"""ORM models for configuration plans (Wave 1 table; planner in Step 9)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import PlanStatus


class ConfigurationPlan(BaseModel):
    """Technician-approved desired state derived from a discovery snapshot.

    Wave 1 Step 6 creates the table only — plan building/approval APIs land
    in later planner steps. ``snapshot_id`` is RESTRICT so a plan always
    references a real capture row.
    """

    __tablename__ = "configuration_plans"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("router_snapshots.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20), default=PlanStatus.DRAFT.value, nullable=False
    )
    engine_version: Mapped[str] = mapped_column(String(20), nullable=False)
    requested_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    actions: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    conflicts: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rendered_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    pre_apply_backup_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("config_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_configuration_plans_router_id", "router_id"),
        Index("ix_configuration_plans_organization_id", "organization_id"),
        Index("ix_configuration_plans_snapshot_id", "snapshot_id"),
    )


__all__ = ["ConfigurationPlan"]

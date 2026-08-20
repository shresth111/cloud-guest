"""ORM model for structured verification runs (WAN / final / plan_step)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class VerificationRun(BaseModel):
    """One structured verification execution for a router (optionally one WAN).

    ``run_group_id`` ties per-link WAN runs from a single API call together
    for gate checks. ``checks`` holds
    ``{name, status, observed, expected, detail, duration_ms}`` items.
    """

    __tablename__ = "verification_runs"

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
    scope: Mapped[str] = mapped_column(String(20), nullable=False)
    run_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_plans.id", ondelete="SET NULL"),
        nullable=True,
    )
    isp_link_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_links.id", ondelete="SET NULL"),
        nullable=True,
    )
    overall: Mapped[str] = mapped_column(String(20), nullable=False)
    checks: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_verification_runs_router_id", "router_id"),
        Index("ix_verification_runs_organization_id", "organization_id"),
        Index("ix_verification_runs_run_group_id", "run_group_id"),
        Index("ix_verification_runs_isp_link_id", "isp_link_id"),
    )


__all__ = ["VerificationRun"]

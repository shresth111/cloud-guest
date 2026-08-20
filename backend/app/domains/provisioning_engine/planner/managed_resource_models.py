"""ORM model for ``managed_router_resources`` (Wave 1 Step 11)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class ManagedRouterResource(BaseModel):
    __tablename__ = "managed_router_resources"

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
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_plans.id", ondelete="SET NULL"),
        nullable=True,
    )
    resource_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    routeros_path: Mapped[str] = mapped_column(String(120), nullable=False)
    comment_tag: Mapped[str] = mapped_column(String(150), nullable=False)
    desired_state_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    op: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_managed_router_resources_router_id", "router_id"),
        Index("ix_managed_router_resources_organization_id", "organization_id"),
        Index("ix_managed_router_resources_comment_tag", "comment_tag"),
    )


__all__ = ["ManagedRouterResource"]

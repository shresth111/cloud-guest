"""ZONE-1: the zone hierarchy. One row per zone that has been placed in the
tree; ``parent_zone_id`` NULL (or no row) = a top-level zone. ``isp_zones``
itself is not altered (ADDENDUM_05 rule: own table, own migration)."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["ZONE_TREE_TABLES", "IspZoneNode"]


class IspZoneNode(BaseModel):
    __tablename__ = "isp_zone_nodes"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_zones.id", ondelete="CASCADE"),
        nullable=False,
    )
    parent_zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_zones.id"), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_zone_nodes_zone",
            "zone_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_isp_zone_nodes_isp_parent", "isp_organization_id", "parent_zone_id"),
    )


ZONE_TREE_TABLES = ("isp_zone_nodes",)

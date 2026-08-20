"""SQLAlchemy ORM model for the Router Readiness Checklist domain.

One table -- ``RouterChecklistItem``, one row per ``(router_id, item_key)``
pair, updated in place on every re-check or manual confirmation -- the same
"one row per subject, updated in place, no history table" convention
``app.domains.router_agent.models.RouterAgentCredential`` already
establishes for its own per-router status half (see that model's own
module docstring). A live-recomputed row (the five ``DetectionMode.AUTO``
items) and a manually-set row (all fourteen, when overridden) share the
exact same schema -- ``detection_mode`` records how *this* row's current
``status`` was produced, not a fixed property of the item.

Does not import ``app.domains.router.models.Router`` -- only FKs its table
name (``"routers.id"``), the same loose-coupling convention
``app.domains.router_provisioning.models``/``app.domains.router_agent
.models`` already establish for their own ``router_id`` columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ChecklistItemStatus


class RouterChecklistItem(BaseModel):
    """One production-readiness checklist item's current state for one
    router. ``item_key`` is one of ``constants.ChecklistItemKey`` (a plain
    string column, not a native enum type, so a new item is always an
    additive registry entry in ``constants.py`` -- never a migration)."""

    __tablename__ = "router_checklist_items"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    item_key: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=ChecklistItemStatus.NOT_CHECKED.value, nullable=False
    )
    detection_mode: Mapped[str] = mapped_column(String(10), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Freeform, item-specific supporting data captured at check time (e.g.
    # the WAN link's own health_status/last_checked_at for
    # wan_connectivity, or the peer's last_handshake_at for wireguard) --
    # shown in the UI as "why this result", never branched on in code.
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Set only when a human produced the current status (confirm_item) --
    # None for an auto-detected result, mirroring
    # app.domains.router_provisioning.models.ConfigVersion's own
    # "created_by null means the system did this" convention.
    checked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        Index("ix_router_checklist_items_router_id", "router_id"),
        Index(
            "uq_router_checklist_items_router_id_item_key",
            "router_id",
            "item_key",
            unique=True,
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<RouterChecklistItem(router_id={self.router_id}, "
            f"item_key={self.item_key}, status={self.status})>"
        )


__all__ = ["RouterChecklistItem"]

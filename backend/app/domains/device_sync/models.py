"""SQLAlchemy ORM model for the Device Synchronization domain.

One table -- ``DeviceSyncRun``. Immutable and append-only once created --
mirrors ``app.domains.provisioning_engine.models.ProvisionJob``'s own
"new row, not mutate" convention: there is no ``update``/soft-delete
method anywhere in this domain's own repository, only ``create`` and
reads. "Sync History" (the roadmap's own named capability) is simply
querying this table, ordered by ``started_at``, never a second table.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does,
even though this domain's own service layer never actually calls
``soft_delete`` -- keeping every table's shape uniform is what lets
``GenericRepository``/Alembic autogenerate/cross-domain FKs keep working
consistently.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import SyncRunStatus


class DeviceSyncRun(BaseModel):
    """One orchestrated "sync this router" attempt -- see module
    docstring. ``component_results`` is a JSONB dict keyed by
    ``constants.SyncComponent`` value, each holding
    ``{"status": ..., "summary": ...}`` -- a real, but variably-shaped,
    per-component result blob, the same real, structured use of JSONB
    ``app.domains.policy.models.PolicyVersion.rules`` already
    establishes for this codebase."""

    __tablename__ = "device_sync_runs"

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
    status: Mapped[str] = mapped_column(
        String(10), default=SyncRunStatus.SUCCESS.value, nullable=False
    )
    component_results: Mapped[dict[str, object]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_device_sync_runs_router_id", "router_id"),
        Index("ix_device_sync_runs_organization_id", "organization_id"),
        Index("ix_device_sync_runs_location_id", "location_id"),
        Index("ix_device_sync_runs_started_at", "started_at"),
        Index("ix_device_sync_runs_status", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<DeviceSyncRun(id={self.id}, router_id={self.router_id}, "
            f"status={self.status})>"
        )


__all__ = ["DeviceSyncRun"]

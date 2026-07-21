"""SQLAlchemy ORM model for the Network Diagnostics domain.

One table -- ``DiagnosticRun``. Immutable and append-only once created --
mirrors ``app.domains.device_sync.models.DeviceSyncRun``'s own "new row,
not mutate" convention: there is no ``update``/soft-delete method
anywhere in this domain's own repository, only ``create`` and reads.
"Diagnostic History" is simply querying this table, ordered by
``created_at``, never a second table.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does,
even though this domain's own service layer never actually calls
``soft_delete``.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DiagnosticStatus


class DiagnosticRun(BaseModel):
    """One real, executed ``ping``/``traceroute`` attempt against a
    router -- see module docstring. ``result`` is a JSONB dict whose real
    shape varies by ``diagnostic_type`` (a ping's ``sent``/``received``/
    ``packet_loss_percentage``/``avg_rtt_ms`` vs. a traceroute's ordered
    ``hops`` list) -- the same real, structured, variably-shaped use of
    JSONB ``app.domains.device_sync.models.DeviceSyncRun
    .component_results`` already establishes for this codebase. Always
    populated even on failure (an empty/partial result), never left
    ``NULL`` -- ``error_message`` carries the failure reason separately."""

    __tablename__ = "diagnostic_runs"

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
    diagnostic_type: Mapped[str] = mapped_column(String(20), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(10), default=DiagnosticStatus.SUCCESS.value, nullable=False
    )
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    executed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_diagnostic_runs_router_id", "router_id"),
        Index("ix_diagnostic_runs_organization_id", "organization_id"),
        Index("ix_diagnostic_runs_location_id", "location_id"),
        Index("ix_diagnostic_runs_diagnostic_type", "diagnostic_type"),
        Index("ix_diagnostic_runs_status", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<DiagnosticRun(id={self.id}, router_id={self.router_id}, "
            f"diagnostic_type={self.diagnostic_type}, status={self.status})>"
        )


__all__ = ["DiagnosticRun"]

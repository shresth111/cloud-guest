"""SQLAlchemy ORM model for router discovery snapshots.

``RouterSnapshot`` is an append-only point-in-time capture of sanitized
RouterOS state. Does not import ``app.domains.router.models.Router`` --
only FKs its table name (``"routers.id"``), the same loose-coupling
convention ``app.domains.router_provisioning.models`` /
``app.domains.readiness.models`` already establish for their own
``router_id`` columns. ``organization_id`` / ``location_id`` are
denormalized from the target router at capture time -- see
``app.domains.guest.models.RadiusNasClient``'s identical convention.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import SnapshotStatus, SnapshotTrigger


class RouterSnapshot(BaseModel):
    """One sanitized discovery capture for one router.

    ``trigger`` / ``status`` are plain string columns holding
    ``SnapshotTrigger`` / ``SnapshotStatus`` values -- never native
    enum types. JSONB section columns never hold secrets (see collector).
    """

    __tablename__ = "router_snapshots"

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
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    trigger: Mapped[str] = mapped_column(
        String(30), default=SnapshotTrigger.WIZARD_DISCOVERY.value, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default=SnapshotStatus.COMPLETE.value, nullable=False
    )
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    routeros_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(50), nullable=True)
    total_memory_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    free_memory_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    free_storage_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    interfaces: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    bridges: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    ip_addresses: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    dhcp_clients: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    dhcp_servers: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    routes: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    dns_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    firewall_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    nat_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    hotspot_state: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    vlans: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    services: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    packages: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)

    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_router_snapshots_router_id", "router_id"),
        Index("ix_router_snapshots_captured_at", "captured_at"),
        Index("ix_router_snapshots_organization_id", "organization_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<RouterSnapshot(id={self.id}, router_id={self.router_id}, "
            f"status={self.status}, captured_at={self.captured_at})>"
        )


__all__ = ["RouterSnapshot"]

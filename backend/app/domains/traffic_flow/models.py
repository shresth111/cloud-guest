"""Traffic flow tables.

``traffic_flow_windows`` -- one row per (router, source, 5-minute window).
Deliberately NOT a ``BaseModel``: telemetry rows are never soft-deleted,
never edited by a user and never versioned, and the audit/soft-delete
columns' indexes are exactly the ``idx_scan = 0`` dead weight dropped from
the other telemetry tables on 2026-09-22.

The unique key is the idempotency guarantee: the pull sweep re-reads
overlapping windows from the hub on purpose (a missed sweep catches up), and
inserts with ON CONFLICT DO NOTHING. ``analytics_snapshots`` had no such key
and ended up 98.8% byte-identical duplicates.

Retention: 7 days (DESIGN.md §5/§7). This is operations data, not the legal
connection record -- Guest Connection Records (``guest_sessions`` /
``guest_login_history``) is, and is never pruned.

``traffic_flow_ingest_state`` -- a single row (``id = 1``) holding the pull
cursor and the last pull's outcome, so the Master view can say
"collector unreachable" or "unknown exporter" instead of showing an empty
table that looks like "no traffic".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDMixin


class TrafficFlowWindow(UUIDMixin, Base):
    __tablename__ = "traffic_flow_windows"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    # Copied from the router at ingest time, for tenant-scoped reads later.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    exporter_address: Mapped[str] = mapped_column(String(45), nullable=False)

    bytes_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flows_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Both ends private (guest -> router DNS, router -> hub over the tunnel).
    bytes_internal: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Both ends public -- should not happen behind NAT; counted, not hidden.
    bytes_unclassified: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    # Bytes outside the stored top-N, per list, so the lists still add up.
    bytes_other_talkers: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    bytes_other_destinations: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    talker_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    destination_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # [{ip, bytes_up, bytes_down, flows, match, guest_session_id}] -- top N
    top_talkers: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    # [{ip, bytes, flows}] -- top N. Never joined to a talker: see package doc.
    top_destinations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint(
            "router_id",
            "source",
            "window_start",
            name="uq_traffic_flow_windows_router_window",
        ),
        Index("ix_traffic_flow_windows_window_start", "window_start"),
    )


class TrafficFlowIngestState(Base):
    __tablename__ = "traffic_flow_ingest_state"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=1)
    # Start of the newest window fully ingested from the hub (epoch seconds
    # as a timestamp). The next pull asks for windows strictly after it.
    last_window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_pull_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_pull_ok: Mapped[bool | None] = mapped_column(nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Exporter addresses seen in the newest pulled window that map to no
    # active WireGuard peer -- e.g. a leaked orphan hub peer. Never guessed.
    unknown_exporters: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

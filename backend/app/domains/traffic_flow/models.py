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

``traffic_flow_service_buckets`` and ``router_traffic_flow_export`` -- see
their class docstrings.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, BaseModel, UUIDMixin


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
    # Client traffic (one private end, one public end), by direction. Their
    # sum is what every share, service row and timeline step is a part of.
    bytes_up: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # False when the collector rows carried no protocol/port, so this window
    # has no service buckets: "not measured", never "no services".
    services_measured: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
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
    # [{ip, bytes, bytes_up, bytes_down, flows}] -- top N. Never joined to a
    # talker: see package doc.
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


class TrafficFlowServiceBucket(Base):
    """One row per (router, source, 5-minute window, protocol, remote port):
    client traffic by *service*, the outside end's port.

    The top ``TOP_SERVICES_STORED`` services of a window get a row each; the
    rest are folded into one "other" row per protocol (``remote_port =
    OTHER_SERVICE_PORT``). Because nothing is dropped, a sum over this table
    is exact -- unlike the per-window top-N talker/destination lists -- and
    the protocol breakdown is a ``GROUP BY protocol``.

    A row holds no address of any kind: not a device, not a destination. It
    is the third independent list, not a pairing (package doc).

    Written once per closed window, together with its ``traffic_flow_windows``
    row and only when that row was new; the unique key plus ON CONFLICT DO
    NOTHING makes a re-pulled window a no-op. Same 7-day delete as windows.
    Not day-partitioned: at this size a bounded DELETE is enough, and
    partitioning would need its own maintenance job (see the PR text)."""

    __tablename__ = "traffic_flow_service_buckets"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
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
    #: IP protocol number (6 TCP, 17 UDP, 1 ICMP, ...).
    protocol: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    #: The outside end's port; 0 for a protocol without ports;
    #: ``OTHER_SERVICE_PORT`` for the folded remainder of this protocol.
    remote_port: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_up: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flows: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: Packets by direction. NULL = not measured: a row written before
    #: packets were recorded (revision 0161), or a window whose collector
    #: rows carried no packet count. Never read NULL as 0.
    packets_up: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    packets_down: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "router_id",
            "source",
            "window_start",
            "protocol",
            "remote_port",
            name="uq_traffic_flow_service_buckets_key",
        ),
        Index("ix_traffic_flow_service_buckets_window_start", "window_start"),
        Index(
            "ix_traffic_flow_service_buckets_location_window",
            "location_id",
            "window_start",
        ),
    )


class RouterTrafficFlowExport(BaseModel):
    """The per-router switch: "Wyfy configured flow export on this router",
    with the last read-back verdict (the ``router_remote_logging`` pattern).
    Replaces the environment allowlist. Not ``routers.settings``: that JSON
    is writable by a venue owner through ``PUT /routers/{id}``."""

    __tablename__ = "router_traffic_flow_export"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: True while Wyfy intends the router to export. False after a removal.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    target_host: Mapped[str | None] = mapped_column(String(45), nullable=True)
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    src_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    export_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    #: When Wyfy last wrote the export onto the router.
    configured_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_verdict_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_verdict_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("router_id", name="uq_router_traffic_flow_export_router_id"),
    )


class TrafficFlowCountryBucket(Base):
    """One row per (router, source, 5-minute window, country, network):
    client traffic by where the outside end is, as DB-IP Lite places it.

    The ``traffic_flow_service_buckets`` pattern with (country, network) in
    place of (protocol, remote port): the window's top countries and top
    networks get rows, the rest are folded into explicit "other" rows, and
    traffic with no country is the "unknown" row -- so a sum over this table
    is exact. The sentinels and the "unknown row is always written" rule are
    in ``geo.py``.

    A row holds no address of any kind, and nothing here is joined to a
    device or a service (package doc). Written once per closed window, only
    when its ``traffic_flow_windows`` row was new and only when the geo data
    files were loaded; unique key plus ON CONFLICT DO NOTHING. Same 7-day
    delete as windows."""

    __tablename__ = "traffic_flow_country_buckets"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
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
    #: ISO 3166-1 alpha-2, or ``geo.UNKNOWN_COUNTRY`` / ``geo.OTHER_COUNTRY``.
    country_code: Mapped[str] = mapped_column(String(8), nullable=False)
    #: AS number; ``geo.UNKNOWN_NETWORK_ASN`` (0) when not known;
    #: ``geo.OTHER_NETWORK_ASN`` (-1) for the country's folded remainder.
    asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: The AS organisation's name at ingest time. A network, not an app.
    network_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bytes_up: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flows: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "router_id",
            "source",
            "window_start",
            "country_code",
            "asn",
            name="uq_traffic_flow_country_buckets_key",
        ),
        Index("ix_traffic_flow_country_buckets_window_start", "window_start"),
        Index(
            "ix_traffic_flow_country_buckets_location_window",
            "location_id",
            "window_start",
        ),
    )


# Registered on the shared metadata with the rest of the domain's tables
# (alembic/env.py imports this module). Defined in its own file.
from .destination_buckets import TrafficFlowDestinationBucket  # noqa: E402, F401
from .flow_record_models import (  # noqa: E402, F401
    TrafficFlowRecord,
    TrafficFlowRecordCap,
)

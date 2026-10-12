"""Destination buckets: the venue's outside addresses by service, per window.

One row says: *this router's venue sent or received N bytes to outside
address A on protocol and port P in this 5-minute window*. It never says
which device did. There is no device address, MAC, guest or session column
here, none is joined, and the reduction that fills the table
(:func:`destination_rows`) is handed the outside end only -- the local end
of each collector row was dropped in ``ingest.reduce_window`` before this
module sees anything.

Do not add a source-device column "for later". A device beside a
destination is the per-guest browsing record the product does not keep
(PRODUCT.md section 5); it is an owner and legal decision, not a schema
convenience.

## Size (why ``TOP_DESTINATION_SERVICES_STORED`` is 50)

RESEARCH.md section 4.1 estimates 15 connections a second for a 50-guest
venue, i.e. about 4,500 connections per 5-minute window, which fold to an
estimated few hundred distinct (address, protocol, port) triples once the
device is dropped. None of that is measured (hardware check H4).

Per router: 288 windows a day x (50 rows + at most ~4 "other" rows, one per
protocol seen) = at most 15,552 rows a day, and 108,864 rows at the 7-day
retention. At roughly 330 bytes a row with its three indexes (about 170 heap,
160 index) that is about 5 MB a day and 36 MB per router at retention; 100
routers would be about 3.6 GB, which is the point to revisit N or partition.
N = 100 would double every figure for the long tail of a list whose head is
what the screen shows.

Everything below the cut is folded into one explicit "other" row per
protocol, so a window's rows add up exactly to its client traffic.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    delete,
    select,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base

from .constants import OTHER_SERVICE_PORT
from .ingest import ExporterWindow

__all__ = [
    "DESTINATION_BUCKET_RETENTION_FACTOR",
    "OTHER_DESTINATION_ADDRESS",
    "TOP_DESTINATION_SERVICES_STORED",
    "TrafficFlowDestinationBucket",
    "destination_bucket_delete_statement",
    "destination_bucket_insert_statement",
    "destination_rows",
]

#: (outside address, protocol, outside port) triples kept per stored window.
#: See the module docstring for the arithmetic.
TOP_DESTINATION_SERVICES_STORED = 50

#: ``remote_address`` of an "other" row. The unspecified address is on the
#: venue side of ``ingest.is_local_address``, so no flow's outside end can
#: carry it. An "other" row is recognised by ``remote_port ==
#: OTHER_SERVICE_PORT``; this value only fills the NOT NULL column so the
#: unique key covers "other" rows too.
OTHER_DESTINATION_ADDRESS = "0.0.0.0"  # noqa: S104 -- a sentinel, not a bind address

#: Destination buckets deleted per sweep, as a multiple of RETENTION_BATCH
#: (about as many rows per window as the service buckets).
DESTINATION_BUCKET_RETENTION_FACTOR = 20


class TrafficFlowDestinationBucket(Base):
    """One row per (router, source, 5-minute window, outside address,
    protocol, outside port). Venue-level and device-free: see the module
    docstring before adding a column.

    Written once per closed window, with its ``traffic_flow_windows`` row
    and only when that row was new; the unique key plus ON CONFLICT DO
    NOTHING makes a re-pulled window a no-op. Same 7-day bounded delete and
    the same scoping columns as ``traffic_flow_service_buckets``."""

    __tablename__ = "traffic_flow_dest_buckets"

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
    #: The outside end's address. ``OTHER_DESTINATION_ADDRESS`` on the
    #: folded remainder. INET so a prefix search is one operator.
    remote_address: Mapped[str] = mapped_column(INET, nullable=False)
    #: IP protocol number (6 TCP, 17 UDP, 1 ICMP, ...).
    protocol: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    #: The outside end's port; 0 for a protocol without ports;
    #: ``OTHER_SERVICE_PORT`` for the folded remainder of this protocol.
    remote_port: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_up: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flows: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "router_id",
            "source",
            "window_start",
            "remote_address",
            "protocol",
            "remote_port",
            name="uq_traffic_flow_dest_buckets_key",
        ),
        Index("ix_traffic_flow_dest_buckets_window_start", "window_start"),
        Index(
            "ix_traffic_flow_dest_buckets_location_window",
            "location_id",
            "window_start",
        ),
    )


def _canonical(address: str) -> str:
    """One spelling per address, so two spellings cannot be two rows."""
    return str(ipaddress.ip_address(address))


def destination_rows(
    window: ExporterWindow, *, limit: int = TOP_DESTINATION_SERVICES_STORED
) -> list[dict[str, Any]]:
    """The window's destination buckets: the top ``limit`` (outside address,
    protocol, outside port) triples by bytes, then everything else folded
    into one row per protocol (``remote_port = OTHER_SERVICE_PORT``).

    Nothing is dropped, so the rows sum to the window's client traffic
    (``bytes_up + bytes_down``) and, per protocol, to its service buckets.
    Empty when the window is not ``services_measured``: a partial list would
    be read as the whole."""
    if not window.services_measured:
        return []
    merged: dict[tuple[str, int, int], list[int]] = {}
    for (address, protocol, port), totals in window.destination_services.items():
        entry = merged.setdefault((_canonical(address), protocol, port), [0, 0, 0])
        for index in range(3):
            entry[index] += totals[index]
    ranked = sorted(merged.items(), key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]))
    rows: list[dict[str, Any]] = [
        {
            "remote_address": address,
            "protocol": protocol,
            "remote_port": port,
            "bytes_up": totals[0],
            "bytes_down": totals[1],
            "flows": totals[2],
        }
        for (address, protocol, port), totals in ranked[:limit]
    ]
    folded: dict[int, list[int]] = {}
    for (_address, protocol, _port), totals in ranked[limit:]:
        rest = folded.setdefault(protocol, [0, 0, 0])
        for index in range(3):
            rest[index] += totals[index]
    rows.extend(
        {
            "remote_address": OTHER_DESTINATION_ADDRESS,
            "protocol": protocol,
            "remote_port": OTHER_SERVICE_PORT,
            "bytes_up": totals[0],
            "bytes_down": totals[1],
            "flows": totals[2],
        }
        for protocol, totals in sorted(folded.items())
    )
    return rows


def destination_bucket_insert_statement(rows: list[dict[str, Any]]) -> Any:
    return (
        pg_insert(TrafficFlowDestinationBucket)
        .values(rows)
        .on_conflict_do_nothing(constraint="uq_traffic_flow_dest_buckets_key")
    )


def destination_bucket_delete_statement(cutoff: datetime, *, limit: int) -> Any:
    """Retention, bounded like the windows and the service buckets."""
    ids = (
        select(TrafficFlowDestinationBucket.id)
        .where(TrafficFlowDestinationBucket.window_start < cutoff)
        .limit(limit)
        .scalar_subquery()
    )
    return delete(TrafficFlowDestinationBucket).where(
        TrafficFlowDestinationBucket.id.in_(ids)
    )

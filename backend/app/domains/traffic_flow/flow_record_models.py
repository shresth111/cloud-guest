"""Tables behind the Master flow table. Split from ``flow_records.py`` only
so ``models.py`` can register them without importing the services. Read
that module's docstring before reading from, or adding a reader to, either
table: a row of ``traffic_flow_records`` puts a device beside the address
it reached."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base

__all__ = ["TrafficFlowRecord", "TrafficFlowRecordCap"]


class TrafficFlowRecord(Base):
    """One flow of one router inside one collector window. See the module
    docstring before reading from, or adding a reader to, this table."""

    __tablename__ = "traffic_flow_records"

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
    #: The collector window the record arrived in. Always known.
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    #: The flow's own first and last packet. NULL = the collector did not
    #: send them; never filled from the window.
    flow_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    flow_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: When the collector received the record (its own clock). NULL = not
    #: recorded.
    arrived_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    src_address: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_address: Mapped[str] = mapped_column(INET, nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: IP protocol number. NULL = not recorded.
    protocol: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    #: The translated addresses, as the exporter reported them. NULL = not
    #: recorded. Never derived from anything else.
    nat_src_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    nat_src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    nat_dst_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    nat_dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    flows: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: ``upload`` / ``download`` / ``internal`` / ``unclassified``.
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    exporter_address: Mapped[str] = mapped_column(String(45), nullable=False)
    #: The exporter's own source port. NULL = not recorded.
    exporter_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: How many collector records this row stands for (1 = not merged).
    records_merged: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    #: True when the merged records differed in the venue-side port, which
    #: is then NULL here. That NULL is "several", not "not recorded".
    ports_merged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    #: NULL = a traffic record. Otherwise an IPFIX NAT event (conntrack
    #: create/delete): the IANA natEvent value, 0 when the hub did not send
    #: the type. Bytes and packets are 0; ``nat_src_*`` is the translation.
    nat_event: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    __table_args__ = (
        Index("ix_traffic_flow_records_window_start", "window_start"),
        Index("ix_traffic_flow_records_router_window", "router_id", "window_start"),
        Index("ix_traffic_flow_records_location_window", "location_id", "window_start"),
    )


class TrafficFlowRecordCap(Base):
    """Per router and UTC day: how many flow records were stored, and, when
    the daily cap stopped storage, since when and how many were not stored.
    The row every reader consults to say "records incomplete since ..."."""

    __tablename__ = "traffic_flow_record_caps"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    day: Mapped[date] = mapped_column(Date, nullable=False)
    rows_stored: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: Start of the first window that was cut or skipped. NULL = not capped.
    capped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rows_not_stored: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: Collector records received for the day, before any rule below.
    rows_received: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    #: Records folded into another row of the same window (not lost: their
    #: bytes, packets and flows are in that row).
    rows_merged: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    #: Records not stored because both ends were inside the venue.
    rows_internal: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint("router_id", "day", name="uq_traffic_flow_record_caps_key"),
        Index("ix_traffic_flow_record_caps_day", "day"),
    )

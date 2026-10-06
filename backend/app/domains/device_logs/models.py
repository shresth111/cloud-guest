"""Device Logs tables.

``device_log_events`` -- the *index* the Master viewer reads: masked
(phones/e-mails), throttled by the collector, append-only. Deliberately not
a ``BaseModel``: no soft delete, no audit/version columns, a bigint
identity key -- a log row is never edited, and six unused columns on the
platform's highest-volume table are pure cost. It is NOT the compliance
record: the collector's raw archive is (DESIGN §7). Prune it (30 days) only
once that archive is live.

``router_remote_logging`` -- the one place "Wyfy configured remote logging
on this router" lives, with the last read-back verdict. Not
``routers.settings``: that JSON is writable by a venue owner through
``PUT /routers/{id}``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

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
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, BaseModel


class DeviceLogEvent(Base):
    __tablename__ = "device_log_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    device_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    facility: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    #: RFC 5424 (0 emergency .. 7 debug). NULL when the line carried no PRI --
    #: never a guessed "info".
    severity: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    topics: Mapped[str | None] = mapped_column(String(200), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    attribution: Mapped[str] = mapped_column(String(32), nullable=False)
    claimed_tag: Mapped[str | None] = mapped_column(String(16), nullable=True)

    __table_args__ = (
        Index("ix_device_log_events_received_at", "received_at"),
        Index("ix_device_log_events_router_received", "router_id", "received_at"),
        Index("ix_device_log_events_org_received", "organization_id", "received_at"),
    )


class RouterRemoteLogging(BaseModel):
    __tablename__ = "router_remote_logging"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
    )
    remote_host: Mapped[str] = mapped_column(String(45), nullable=False)
    remote_port: Mapped[int] = mapped_column(Integer, nullable=False)
    src_address: Mapped[str] = mapped_column(String(45), nullable=False)
    tag: Mapped[str] = mapped_column(String(16), nullable=False)
    #: True while Wyfy intends the router to send. False after a removal.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verify_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("router_id", name="uq_router_remote_logging_router_id"),
    )

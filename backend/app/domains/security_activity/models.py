"""Security activity: hourly hit counters read off each router's own
protection rules.

The only table in this domain, written by exactly one path:
``tasks.collect_security_counters_for_router``, which *reads* a router over 8728 through
``wyfy_device_gateway.read_only_reader.ReadOnlyDeviceReader`` -- an object
that cannot express a write -- and records what it saw here. Nothing in this
domain writes to a router.

## What a row is

One protection rule on one router, for one clock hour (UTC):

* ``packets_delta``/``bytes_delta`` -- what the rule's counters moved during
  that hour, summed over every sample taken in it.
* ``packets_total``/``bytes_total`` -- the raw cumulative counter at the last
  sample, kept so the next sample can compute its delta.

RouterOS counters are cumulative since the rule was added or the router last
rebooted. A total *lower* than the previous one means the counter restarted,
and the new total is then the delta (everything counted since the restart),
never a negative number.

## Retention

Operational telemetry, not a CERT-In connection record. Safe to prune at 90
days alongside ``router_health_snapshots``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDMixin


class SecurityCounterSample(UUIDMixin, Base):
    __tablename__ = "security_counter_samples"

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: ``activity.Protection`` value -- which customer-facing protection
    #: this rule belongs to.
    protection: Mapped[str] = mapped_column(String(40), nullable=False)
    #: Stable identity of the rule on the router: its comment.
    rule_key: Mapped[str] = mapped_column(String(160), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    bucket_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    sampled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    packets_total: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bytes_total: Mapped[int] = mapped_column(BigInteger, nullable=False)
    packets_delta: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_delta: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        Index(
            "uq_security_counter_samples_router_rule_bucket",
            "router_id",
            "rule_key",
            "bucket_start",
            unique=True,
        ),
        Index(
            "ix_security_counter_samples_org_bucket",
            "organization_id",
            "bucket_start",
        ),
    )


__all__ = ["SecurityCounterSample"]

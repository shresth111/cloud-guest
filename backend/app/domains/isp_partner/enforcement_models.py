"""JAZE-2 tables (ADDENDUM_05 J3 + J8): package policy, per-subscriber usage,
MAC/IP bindings and an enforcement event log.

New tables only, all keyed by ``subscriber_id`` / ``package_id``; no column is
added to ``isp_subscribers`` or ``isp_packages``. Everything is read only
while ``ISP_PARTNER_ENFORCEMENT_ENABLED`` is on (default off).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "ENFORCEMENT_TABLES",
    "IspEnforcementEvent",
    "IspPackagePolicy",
    "IspSubscriberIpBinding",
    "IspSubscriberMacBinding",
    "IspSubscriberUsage",
]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspPackagePolicy(BaseModel):
    """One row per package: FUP, night boost, validity start, access rules."""

    __tablename__ = "isp_package_policies"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    package_id: Mapped[uuid.UUID] = _fk("isp_packages.id", ondelete="CASCADE")

    # FUP. NULL limit = no FUP.
    fup_limit_mb: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: cycle | day | month
    fup_reset: Mapped[str] = mapped_column(
        String(8), nullable=False, server_default="cycle"
    )
    fup_fallback_speed_group_id: Mapped[uuid.UUID | None] = _fk(
        "isp_speed_groups.id", nullable=True
    )
    fup_exclude_upload: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    fup_carry_forward: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )

    # Time-of-day override ("night boost"), minutes after local midnight in
    # the customer's timezone. end < start wraps past midnight.
    boost_speed_group_id: Mapped[uuid.UUID | None] = _fk(
        "isp_speed_groups.id", nullable=True
    )
    boost_start_minute: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    boost_end_minute: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    #: last state the sweep saw, so a window edge is acted on once
    boost_state_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )

    #: activation | first_login
    validity_starts: Mapped[str] = mapped_column(
        String(12), nullable=False, server_default="activation"
    )
    #: 1 (highest) .. 8; NULL = the speed group's own priority
    queue_priority: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    # Access rules (enforced by the sweep, see enforcement.py).
    mac_bind_count: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="0"
    )
    mac_restriction: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    ip_restriction: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    max_simultaneous: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    idle_timeout_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hard_timeout_s: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_package_policies_package",
            "package_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_isp_package_policies_isp", "isp_organization_id"),
    )


class IspSubscriberUsage(BaseModel):
    """The current FUP period's counters for one subscriber."""

    __tablename__ = "isp_subscriber_usage"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id", ondelete="CASCADE")
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_down_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    used_up_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    carry_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    throttled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    throttled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: bytes added by the ISP as a top-up for this period
    topup_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    last_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_subscriber_usage_subscriber",
            "subscriber_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspSubscriberMacBinding(BaseModel):
    __tablename__ = "isp_subscriber_mac_bindings"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id", ondelete="CASCADE")
    mac: Mapped[str] = mapped_column(String(17), nullable=False)
    #: auto | manual
    source: Mapped[str] = mapped_column(String(8), nullable=False)

    __table_args__ = (
        Index(
            "uq_isp_subscriber_mac_bindings_sub_mac",
            "subscriber_id",
            "mac",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspSubscriberIpBinding(BaseModel):
    """A static IP (from an existing DHCP pool) pinned to a subscriber."""

    __tablename__ = "isp_subscriber_ip_bindings"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id", ondelete="CASCADE")
    location_id: Mapped[uuid.UUID] = _fk("locations.id")
    router_id: Mapped[uuid.UUID | None] = _fk("routers.id", nullable=True)
    dhcp_pool_id: Mapped[uuid.UUID | None] = _fk("dhcp_pools.id", nullable=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    static_queue: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    queue_assignment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    #: none | active | failed
    queue_status: Mapped[str] = mapped_column(
        String(8), nullable=False, server_default="none"
    )
    queue_error: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_subscriber_ip_bindings_location_ip",
            "location_id",
            "ip",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_isp_subscriber_ip_bindings_subscriber", "subscriber_id"),
    )


class IspEnforcementEvent(BaseModel):
    """What the sweep did, for the subscriber 360 timeline."""

    __tablename__ = "isp_enforcement_events"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id", ondelete="CASCADE")
    #: see enforcement.EVENT_KINDS
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_isp_enforcement_events_sub_time", "subscriber_id", "occurred_at"),
    )


ENFORCEMENT_TABLES = (
    "isp_package_policies",
    "isp_subscriber_usage",
    "isp_subscriber_mac_bindings",
    "isp_subscriber_ip_bindings",
    "isp_enforcement_events",
)

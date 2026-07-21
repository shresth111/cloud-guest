"""SQLAlchemy ORM models for the ISP Management domain.

Both tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

## Two tables, not three -- "current state + history", mirroring
## ``app.domains.monitoring``'s own established split

``app.domains.monitoring``'s own module docstring documents a deliberate
choice: a device's *current* health lives as columns on its own row
(``Router.health_status``/``last_seen_at``/``last_health_check_at``), while
its *history* lives in a separate, append-only time-series table
(``HealthCheck``) -- never a third, redundant "current status" table
layered on top. This domain follows the identical split:

* :class:`IspLink` -- one row per WAN uplink a router carries, holding its
  *current* health snapshot (``health_status``/``latency_ms``/
  ``packet_loss_percentage``/``last_checked_at``) directly as columns,
  updated in place by every health check.
* :class:`IspHealthCheck` -- one row per health-check *execution*, an
  append-only log mirroring ``monitoring.models.HealthCheck``'s identical
  shape (``checked_at``, ``status``, a response-time-style float, an
  optional error message) -- this is what "History" (the roadmap's own
  named capability) means concretely: querying this table ordered by
  ``checked_at``, never a second live-state table.

Failover *events* (a link flipping ``is_active_uplink``) are **not** a
third table either -- see ``service.py``'s module docstring for why those
are written to RBAC's own ``audit_log_entries`` (a real, admin-relevant,
moderate-volume state change), while the frequent, high-volume per-tick
health readings above are not (mirrors
``app.domains.guest.service``'s own "high-volume, no per-call audit row"
judgment call for login attempts).

## Why ``router_id``, not ``location_id``

An ISP/WAN link is physically terminated at one router (the device with
the actual WAN interface) -- ``location_id``/``organization_id`` are
denormalized from the owning ``Router`` at creation time (mirrors
``GuestSession.organization_id``'s identical "denormalize onto every child
table at write time" convention), immutable after creation exactly like
``Router.location_id``/``organization_id`` themselves.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import HealthStatus, IspLinkType


class IspLink(BaseModel):
    """One WAN uplink a router carries -- see module docstring for the
    "current state, not history" scope of this row, and
    ``constants.IspLinkRole``'s own docstring for the ``role`` vs.
    ``is_active_uplink`` distinction (a router's static priority
    assignment vs. which link is *actually* live right now)."""

    __tablename__ = "isp_links"

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
    provider_name: Mapped[str] = mapped_column(String(200), nullable=False)
    link_type: Mapped[str] = mapped_column(
        String(20), default=IspLinkType.OTHER.value, nullable=False
    )
    role: Mapped[str] = mapped_column(String(10), nullable=False)
    # Which link is *currently* carrying traffic -- flips during a real
    # failover/failback, independent of the static `role` assignment above.
    # At most one row per router may have this `true` -- enforced by the
    # partial unique index below, mirroring
    # app.domains.guest_teams.models.GuestTeamMember's identical
    # partial-unique-index precedent for "at most one active X per scope".
    is_active_uplink: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # Only meaningful on the PRIMARY row: whether recovering from a
    # failover should automatically hand traffic back to this link once it
    # is HEALTHY again, or wait for an admin to call resume_primary
    # explicitly. See service.py's own failover/failback write-up.
    auto_failback: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # An admin's own reversible "take this link out of service" toggle --
    # distinct from health_status (a disabled link is never health-checked
    # or considered for failover at all, not merely reported unhealthy).
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # A router may carry more than one BACKUP link -- `priority` (lower
    # value tried first) picks which enabled, non-unhealthy backup
    # `trigger_failover` fails over to when several exist. Meaningless
    # for the single PRIMARY row (there is only ever one), but still
    # stored uniformly rather than made nullable-only-for-backups, so
    # ordering a router's own links by (role, priority) is always a
    # single, unconditional query.
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # The router's own WAN-facing interface name this link terminates on
    # (e.g. "ether1", "sfp1") -- informational/provisioning-facing only,
    # mirrors `link_type`'s identical "not branched on internally" scope.
    interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    gateway_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dns_primary: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dns_secondary: Mapped[str | None] = mapped_column(String(45), nullable=True)
    download_bandwidth_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    upload_bandwidth_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # NULL/UNKNOWN until the first real health check ever runs -- see
    # constants.HealthStatus's own docstring for why this is never
    # defaulted to HEALTHY.
    health_status: Mapped[str] = mapped_column(
        String(20), default=HealthStatus.UNKNOWN.value, nullable=False
    )
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_percentage: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Consecutive UNHEALTHY readings -- reset to 0 the moment a check comes
    # back HEALTHY or DEGRADED. Drives
    # constants.DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER.
    consecutive_unhealthy_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    __table_args__ = (
        Index("ix_isp_links_router_id", "router_id"),
        Index("ix_isp_links_organization_id", "organization_id"),
        Index("ix_isp_links_location_id", "location_id"),
        Index("ix_isp_links_role", "role"),
        Index("ix_isp_links_health_status", "health_status"),
        Index("ix_isp_links_is_enabled", "is_enabled"),
        Index(
            "uq_isp_links_router_id_active_uplink",
            "router_id",
            unique=True,
            postgresql_where=text("is_active_uplink = true AND is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<IspLink(id={self.id}, provider_name={self.provider_name}, "
            f"role={self.role})>"
        )


class IspHealthCheck(BaseModel):
    """One row per real health-check execution against an
    :class:`IspLink`'s own ``gateway_ip_address`` -- an append-only
    time-series log, mirroring
    ``app.domains.monitoring.models.HealthCheck``'s identical shape. This
    is what "History" means concretely -- see module docstring."""

    __tablename__ = "isp_health_checks"

    isp_link_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_links.id", ondelete="CASCADE"),
        nullable=False,
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_percentage: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_isp_health_checks_isp_link_id", "isp_link_id"),
        Index("ix_isp_health_checks_checked_at", "checked_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<IspHealthCheck(isp_link_id={self.isp_link_id}, "
            f"status={self.status}, checked_at={self.checked_at})>"
        )


__all__ = ["IspLink", "IspHealthCheck"]

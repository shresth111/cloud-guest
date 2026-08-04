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

## Manual status override: a source tag, not a third status vocabulary

The dashboard's "Internet Connection" view is read/observe-only -- it
never pushes real config to a router. The one *write* it does offer is a
human override of a link's own current status (see ``IspService
.set_manual_health_status``), for when an admin knows a link is up/down
before (or instead of) the next automated sweep tick confirms it. That
override is real and persisted -- both tables gain a ``source`` column
(``constants.HealthStatusSource``: ``AUTOMATED``/``MANUAL``) rather than a
second status vocabulary, so the "Status Timeline" built from
``IspHealthCheck`` history renders manual and real readings on one
uniform scale. The very next real ping always reclaims a link back to
``AUTOMATED`` -- an override is a point-in-time statement, never a
permanent lockout of the real health-check sweep.

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
    BigInteger,
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

from .constants import HealthStatus, HealthStatusSource, IspConnectionMode, IspLinkType


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
    # How this link's own gateway/IP is actually obtained -- STATIC/DHCP/
    # PPPOE, orthogonal to link_type above (physical medium). Drives which
    # real health-check target-resolution strategy IspService.ping_link
    # uses; see constants.IspConnectionMode's own docstring. Defaults to
    # STATIC -- every pre-existing row really was a manually-entered
    # gateway IP before this field existed.
    connection_mode: Mapped[str] = mapped_column(
        String(20), default=IspConnectionMode.STATIC.value, nullable=False
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
    # (e.g. "ether1", "sfp1") -- informational/provisioning-facing only
    # for STATIC/DHCP links (mirrors `link_type`'s identical "not branched
    # on internally" scope), but for a PPPOE link (connection_mode above)
    # this field IS branched on internally: it names the real RouterOS
    # `/interface/pppoe-client` entry IspService.ping_link checks for its
    # own running/disabled state as that link's actual health signal (see
    # device_adapters.get_pppoe_interface_status). A stale/renamed value
    # here degrades gracefully rather than hard-failing -- see that
    # adapter method's own single-candidate-fallback docstring.
    interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # STATIC mode only -- the manually-entered ping target. Never read for
    # DHCP (re-resolved live every check from the router's own current
    # dynamic default route) or PPPOE (no gateway concept at all) -- see
    # constants.IspConnectionMode's own docstring.
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
    # Whether the *current* health_status above came from a real RouterOS
    # ping (AUTOMATED -- the sweep or a manual on-demand check) or an
    # admin's own override (MANUAL -- see IspService
    # .set_manual_health_status). The next real ping always reclaims this
    # back to AUTOMATED (record_health_check_result writes it
    # unconditionally) -- see constants.HealthStatusSource's own
    # docstring.
    health_status_source: Mapped[str] = mapped_column(
        String(20), default=HealthStatusSource.AUTOMATED.value, nullable=False
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
    # Live traffic-load monitoring -- "how much traffic is flowing on
    # this link right now", distinct from download_bandwidth_mbps/
    # upload_bandwidth_mbps above (the link's *provisioned* plan
    # capacity, e.g. "500 Mbps fiber", never measured). Sampled from the
    # router's own interface byte counters (rx-byte/tx-byte on
    # `interface` -- for PPPOE links this is the PPPoE client's own
    # virtual interface, which carries its own independent counters, not
    # the underlying physical interface) every health check, on every
    # connection mode uniformly -- see IspService.sample_link_traffic.
    # last_rx_bytes/last_tx_bytes are the raw cumulative counters from
    # the most recent successful sample, kept only to compute the next
    # tick's delta -- never displayed directly (mirrors
    # app.domains.guest.service's own "counter now, delta computed
    # against the previous reading" convention). A counter that goes
    # backwards (interface reset/reboot) yields no rate that tick rather
    # than a garbage negative one -- see that method's own docstring.
    last_rx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_tx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The most recently *computed* rate -- current state, mirroring this
    # table's own "current state, not history" split (see module
    # docstring); IspHealthCheck.download_mbps/upload_mbps is the history.
    current_download_mbps: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    current_upload_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)

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
    # AUTOMATED for a real /tool/ping row (sweep or manual on-demand
    # check), MANUAL for a synthetic row written by an admin's own status
    # override (IspService.set_manual_health_status) -- see
    # constants.HealthStatusSource. The "Status Timeline" this history
    # backs renders both uniformly, distinguishing them only visually.
    source: Mapped[str] = mapped_column(
        String(20), default=HealthStatusSource.AUTOMATED.value, nullable=False
    )
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_percentage: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Live traffic-load reading for this same tick -- null whenever a
    # rate genuinely couldn't be computed yet (the link's very first
    # sample ever, a manual status override with no real device read, or
    # a counter that went backwards -- see IspService
    # .sample_link_traffic's own docstring), never a fabricated 0. This
    # is what the "Traffic Load" graph renders from -- the exact same
    # history rows the up/down "Status Timeline" already uses, not a
    # second, parallel monitoring table.
    download_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    upload_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_isp_health_checks_isp_link_id", "isp_link_id"),
        Index("ix_isp_health_checks_checked_at", "checked_at"),
        # The real, dominant access pattern for this table -- both
        # IspRepository.list_health_checks_for_link's date-range branch and
        # bucketed_health_checks_for_link (the Bandwidth Utilization/
        # history-dialog aggregation) filter `isp_link_id == X AND
        # checked_at BETWEEN start AND end` together, never one alone. The
        # two single-column indexes above force a bitmap-AND; at real scale
        # (tens of thousands of rows per link after a few weeks at the
        # sweep's 60s cadence, per this table's own module docstring) a
        # single composite index serving that exact predicate directly is
        # the difference between an index range scan and a much costlier
        # plan. Column order matters: isp_link_id first (the always-present
        # equality filter) then checked_at (the range filter), the
        # standard equality-then-range composite-index ordering.
        Index(
            "ix_isp_health_checks_link_id_checked_at",
            "isp_link_id",
            "checked_at",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<IspHealthCheck(isp_link_id={self.isp_link_id}, "
            f"status={self.status}, checked_at={self.checked_at})>"
        )


__all__ = ["IspLink", "IspHealthCheck"]

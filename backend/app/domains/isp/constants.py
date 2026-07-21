"""Enumerations and small constants for the ISP Management domain.

Stored as plain ``String`` columns on the ORM models, never native
PostgreSQL enum types -- the same reason every other domain in this
codebase documents (``app.domains.otp.constants``,
``app.domains.voucher.constants``, ``app.domains.rbac.enums``): adding a
new value never requires an ``ALTER TYPE`` migration, only a new additive
``StrEnum`` member.

``HealthStatus`` is defined locally, not imported from
``app.domains.monitoring.constants`` -- mirrors
``app.domains.wireguard.constants.HealthStatus``'s identical "each domain
defines its own small, analogous health vocabulary rather than cross-
importing a plain value enum" precedent (this codebase's leaf-module
discipline is about avoiding coupling for genuine business logic, not
about sharing a trivial four-value enum). Unlike WireGuard's own
``HealthStatus`` (a pure, never-persisted, read-time-computed signal from
staleness alone), this domain's ``IspLink.health_status`` **is** persisted
-- it is the result of a real, periodic RouterOS ``/tool/ping`` measurement
(see ``device_adapters.py``), not merely "how long ago was the last
check."

**No new ``Settings`` fields.** Like ``app.domains.monitoring``/
``app.domains.queue_management``, every tunable threshold below lives here
as a plain module constant, not a new ``Settings`` field or
``Organization.settings`` key -- see ``docs/isp/FLOW.md`` for why
per-organization tunability is deliberately out of this iteration's scope.
"""

from __future__ import annotations

from enum import StrEnum


class IspLinkType(StrEnum):
    """The physical/connection technology an ISP link uses -- informational
    only (nothing in this domain branches its own logic on link type; it
    exists for admin-facing display and reporting)."""

    FIBER = "fiber"
    DSL = "dsl"
    CABLE = "cable"
    WIRELESS_4G = "wireless_4g"
    WIRELESS_5G = "wireless_5g"
    SATELLITE = "satellite"
    LEASED_LINE = "leased_line"
    OTHER = "other"


class IspLinkRole(StrEnum):
    """A router's own static, admin-assigned uplink priority -- distinct
    from :attr:`~.models.IspLink.is_active_uplink` (which link is
    *currently* carrying traffic right now). A router has exactly one
    ``PRIMARY`` link and zero or more ``BACKUP`` links; failover flips
    which link is active without ever changing this field."""

    PRIMARY = "primary"
    BACKUP = "backup"


class HealthStatus(StrEnum):
    """The result of the most recent real health check
    (``device_adapters.BaseIspHealthAdapter.ping``) against a link's own
    ``gateway_ip_address``. ``UNKNOWN`` is the default for a link that has
    never been checked yet (not "assumed healthy") -- the identical
    "no fake opinion before real data exists" posture
    ``app.domains.router.models.Router.health_status`` (``NULL`` until
    first heartbeat) and this codebase's Queue Management Engine's own
    "Unlimited" fallback profile already establish."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# ============================================================================
# Health-check classification thresholds -- see
# ``validators.classify_health_status``. Deliberately plain module
# constants (not ``Settings``/``Organization.settings``): full
# per-organization tunability is a real future seam (mirrors
# ``app.domains.guest.constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST``'s
# own "single honest platform-wide default until the Policy Engine grows a
# seam for it" posture), not implemented in this first pass.
# ============================================================================

DEFAULT_LATENCY_DEGRADED_THRESHOLD_MS = 150.0
DEFAULT_LATENCY_UNHEALTHY_THRESHOLD_MS = 400.0
DEFAULT_PACKET_LOSS_DEGRADED_THRESHOLD_PERCENT = 5.0
DEFAULT_PACKET_LOSS_UNHEALTHY_THRESHOLD_PERCENT = 20.0

# How many *consecutive* UNHEALTHY checks a PRIMARY link must accumulate
# before the health-check sweep triggers a real failover to a BACKUP --
# deliberately more than 1: a single bad ping (a transient blip, not a real
# outage) must never flap a guest network's live uplink back and forth.
# DEGRADED never counts toward this threshold at all (still functional,
# merely worth alerting on) -- only genuine UNHEALTHY readings accumulate.
DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER = 3

# Real RouterOS /tool/ping parameters -- see device_adapters.py.
ISP_PING_COUNT = 5
ISP_PING_TIMEOUT_SECONDS = 10

# ============================================================================
# Health-check sweep -- Celery Beat task wiring. Every 60 seconds: a WAN
# uplink failing is exactly as operationally urgent as a stale guest
# session (see app.domains.guest.constants
# .SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS's own 5-minute cadence
# reasoning) -- arguably more so, since every guest at a site rides on
# whichever link is currently active, hence a tighter interval than that
# precedent.
# ============================================================================

TASK_RUN_ISP_HEALTH_CHECK_SWEEP = "app.domains.isp.tasks.run_isp_health_check_sweep"
ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS = 60.0


__all__ = [
    "IspLinkType",
    "IspLinkRole",
    "HealthStatus",
    "DEFAULT_LATENCY_DEGRADED_THRESHOLD_MS",
    "DEFAULT_LATENCY_UNHEALTHY_THRESHOLD_MS",
    "DEFAULT_PACKET_LOSS_DEGRADED_THRESHOLD_PERCENT",
    "DEFAULT_PACKET_LOSS_UNHEALTHY_THRESHOLD_PERCENT",
    "DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER",
    "ISP_PING_COUNT",
    "ISP_PING_TIMEOUT_SECONDS",
    "TASK_RUN_ISP_HEALTH_CHECK_SWEEP",
    "ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS",
]

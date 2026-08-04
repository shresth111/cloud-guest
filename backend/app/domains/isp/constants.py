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


class IspConnectionMode(StrEnum):
    """How this WAN link actually obtains its own gateway/IP configuration
    -- drives which real health-check *target-resolution* strategy
    ``IspService.ping_link`` uses (see ``device_adapters.py``'s own module
    docstring for the real RouterOS calls each one issues). Deliberately
    its own field, never folded into :class:`IspLinkType` -- a fiber
    connection can be ``STATIC``, ``DHCP``, or ``PPPOE``-authenticated all
    the same (the two are orthogonal: one is the physical medium, this is
    the addressing/authentication mode on top of it), so conflating them
    would make ``IspLinkType`` lie about a link's real physical medium the
    moment an admin needed to record its addressing mode.

    * ``STATIC`` -- a fixed, admin-known gateway IP (``IspLink
      .gateway_ip_address``, typed in once). The original, only-ever-
      supported mode -- default for every pre-existing row.
    * ``DHCP`` -- the gateway is assigned dynamically by the ISP and can
      change at any time. Never typed in manually -- resolved live at
      every health check from the router's own *current* dynamic default
      route (``/ip route print`` where ``dst-address=0.0.0.0/0`` and
      ``dynamic=true``), so a re-lease never goes stale against a
      manually-entered value nobody updated.
    * ``PPPOE`` -- no IP-layer gateway concept at all; health is the
      PPPoE client interface's own up/down (``running``/``disabled``)
      state, checked directly rather than pinged.
    """

    STATIC = "static"
    DHCP = "dhcp"
    PPPOE = "pppoe"


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


class HealthStatusSource(StrEnum):
    """Where a link's own *current* ``IspLink.health_status`` (and each
    ``IspHealthCheck`` row's own ``status``) actually came from --
    ``AUTOMATED`` for a real RouterOS ``/tool/ping`` reading (the sweep or
    a manual on-demand check), ``MANUAL`` for an admin's own override (see
    ``IspService.set_manual_health_status``). Deliberately a source tag on
    the *existing* ``healthy``/``degraded``/``unhealthy``/``unknown``
    vocabulary, never a parallel status enum -- the founder's own
    "map onto the existing healthy/unhealthy vocabulary, don't invent a
    new one" instruction. The *next* real ping naturally reclaims a link
    back to ``AUTOMATED`` (``record_health_check_result`` always writes
    this field), so a manual override is a point-in-time statement, not a
    permanent lockout of the real health-check sweep."""

    AUTOMATED = "automated"
    MANUAL = "manual"


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
# On-demand "Run Speed Test" -- real RouterOS /tool/fetch download, see
# device_adapters.py's run_speed_test docstring for the full "why this
# command, why this size" write-up. Confirmed against the real test org's
# real MikroTik hEX lite router (RouterOS 7.16.2) over its real Airtel WAN
# link: a 10MB fetch against this exact URL took 6 real seconds and
# transferred 9765 real KiB (~13.3 Mbps) -- a real, repeatable measurement,
# not a guess at a "reasonable" size.
#
# Cloudflare's own public `/__down?bytes=N` speed-test endpoint is used
# (not a fixed-size file like Hetzner's speedtest hosts) specifically
# because it lets this platform control the exact payload size -- kept
# modest (10MB, not tens/hundreds of MB) since the real target hardware
# (hEX lite: 1 CPU core, 64MB RAM, 16MB flash) is genuinely low-power and
# this is a user-triggered, one-link-at-a-time action, never a scheduled
# sweep.
SPEED_TEST_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
# The RouterOS API connection timeout for this specific action only (never
# applied to the fast, routine ISP_PING_TIMEOUT_SECONDS health-check path)
# -- must genuinely exceed the real download's own expected duration. A
# slow-but-real WAN link (e.g. ~2 Mbps) could take ~40s to move 10MB; 60s
# leaves real headroom without being open-ended.
SPEED_TEST_TIMEOUT_SECONDS = 60

# Real bandwidth-abuse/self-congestion guard: this action genuinely
# consumes a customer's own (possibly metered) WAN bandwidth and briefly
# saturates a low-power router -- unlike every other RBAC-gated ISP
# endpoint, repeating it back-to-back has a real external cost, so it gets
# a real per-link cooldown, enforced in Redis by IspService.run_speed_test
# (mirrors app.domains.otp.service.OtpRateLimiter's identical
# SET-NX-EX-then-check-TTL pattern, keyed by isp_link_id instead of an OTP
# identifier). Deliberately shorter than SPEED_TEST_TIMEOUT_SECONDS itself
# would allow back-to-back tests the instant one finishes, so this is its
# own, separate, slightly-longer-than-worst-case-duration value.
SPEED_TEST_MIN_INTERVAL_SECONDS = 60
SPEED_TEST_COOLDOWN_REDIS_KEY_TEMPLATE = "isp:speed_test:cooldown:{link_id}"
# Set for the real duration of an in-flight speed test (TTL'd well past
# SPEED_TEST_TIMEOUT_SECONDS as a safety net in case a request dies
# without reaching the `finally` that clears it) -- checked by
# IspService.record_health_check_result so the *automated* 60s sweep's own
# concurrent ping against the same link, if it lands mid-test, never lets
# a purely self-induced congestion reading advance
# consecutive_unhealthy_count toward a real failover. See that method's
# own docstring for the full "why this matters" write-up.
SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE = "isp:speed_test:active:{link_id}"
SPEED_TEST_ACTIVE_REDIS_TTL_SECONDS = SPEED_TEST_TIMEOUT_SECONDS + 30

# How far back (in real IspHealthCheck rows) IspService
# .compute_unhealthy_since is willing to scan looking for where the
# link's *current* unbroken UNHEALTHY streak actually began -- capped,
# not unbounded, mirroring this domain's "small, proportionate, never a
# full historical-analytics system" scope elsewhere (e.g.
# compute_availability_percentage's own bounded page). At the sweep's own
# 60-second cadence this covers a little over 3 hours of continuous
# downtime before falling back to reporting the window's own oldest
# checked_at as an honest lower bound rather than an exact instant.
UNHEALTHY_SINCE_LOOKBACK_LIMIT = 200

# ============================================================================
# Health-check sweep -- Celery Beat task wiring.
#
# Was 60 seconds (a WAN uplink failing is exactly as operationally urgent
# as a stale guest session -- see app.domains.guest.constants
# .SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS's own 5-minute cadence
# reasoning -- arguably more so). Raised to 10 minutes: the sweep
# (service.run_health_check_sweep) is a single Celery Beat task that
# fetches every enabled IspLink platform-wide and health-checks them
# **sequentially, one real RouterOS API connection at a time**, in one
# plain `for` loop inside one task run -- not fanned out per-link/
# per-router, and this codebase has no overlap-prevention lock on any
# Celery Beat task (here or elsewhere). At real scale (1000+ links) a
# real RouterOS connection+ping is meaningfully more expensive than a
# bare ICMP ping from a control server, so a 60-second interval risked
# the sweep's own wall-clock runtime exceeding the interval itself and
# queuing up overlapping runs -- a materially bigger risk than any single
# link's own API load. 10 minutes is a real, accepted mitigation (fewer,
# less-frequent runs), not a full fix -- true safety at 1000+ links still
# needs either bounded concurrency within one sweep run (e.g.
# `asyncio.gather` with a semaphore) or an overlap-prevention lock so a
# slow run is skipped-not-queued rather than doubled up; out of scope for
# this pass, flagged here for whoever picks up that follow-on work.
# ============================================================================

TASK_RUN_ISP_HEALTH_CHECK_SWEEP = "app.domains.isp.tasks.run_isp_health_check_sweep"
# Lowered back to the original 60s (from the 600s documented above) for a
# real-time feel at today's real scale (a handful of links, not 1000+) --
# confirmed live: a real WAN disconnect on the one live test router sat
# undetected for 10+ minutes at 600s, which reads as "broken monitoring"
# to an operator watching it happen. The scale risk documented above still
# applies once link count grows -- whoever revisits this at real scale
# should raise it again (or better, build the bounded-concurrency/overlap
# lock this comment already flags) rather than silently leaving it at 60s
# forever.
ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS = 60.0


__all__ = [
    "IspLinkType",
    "IspConnectionMode",
    "IspLinkRole",
    "HealthStatus",
    "HealthStatusSource",
    "DEFAULT_LATENCY_DEGRADED_THRESHOLD_MS",
    "DEFAULT_LATENCY_UNHEALTHY_THRESHOLD_MS",
    "DEFAULT_PACKET_LOSS_DEGRADED_THRESHOLD_PERCENT",
    "DEFAULT_PACKET_LOSS_UNHEALTHY_THRESHOLD_PERCENT",
    "DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER",
    "ISP_PING_COUNT",
    "ISP_PING_TIMEOUT_SECONDS",
    "SPEED_TEST_DOWNLOAD_URL",
    "SPEED_TEST_TIMEOUT_SECONDS",
    "SPEED_TEST_MIN_INTERVAL_SECONDS",
    "SPEED_TEST_COOLDOWN_REDIS_KEY_TEMPLATE",
    "SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE",
    "SPEED_TEST_ACTIVE_REDIS_TTL_SECONDS",
    "UNHEALTHY_SINCE_LOOKBACK_LIMIT",
    "TASK_RUN_ISP_HEALTH_CHECK_SWEEP",
    "ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS",
]

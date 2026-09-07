"""Celery Beat task wiring for the Router domain.

Every other domain in this codebase that owns a Beat-scheduled sweep keeps
its task name/interval constants in a dedicated ``constants.py`` (see
``app.domains.guest.constants``, ``app.domains.isp.constants``,
``app.domains.connected_devices.constants``, ...) -- this module's own
enum-shaped values already live in ``enums.py`` (``RouterStatus``/
``ROUTER_STATUS_TRANSITIONS``/``RouterHealthStatus``), so this file is
purely additive: just the one sweep's task name + cadence, following the
same "never a bare magic number in ``app.core.celery_app``" convention
every other sweep in that module's own ``beat_schedule`` already follows.
"""

from __future__ import annotations

# ============================================================================
# Enrollment token expiry cleanup sweep -- see
# ``service.RouterService.sweep_expired_provisioning_tokens``'s own
# docstring and ``tasks.run_provisioning_token_cleanup_sweep``'s own
# docstring.
# ============================================================================

TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP = (
    "app.domains.router.tasks.run_provisioning_token_cleanup_sweep"
)

# Once per hour -- an expired-but-unused RouterProvisioningToken is already
# fully inert the moment it expires (``check_in`` rejects it via
# ``ProvisioningTokenExpiredError`` regardless of whether this sweep has
# gotten to it yet); soft-deleting it is pure housekeeping with no
# operationally-visible urgency, the identical "day/week/month rollover
# boundary never needs finer-than-hourly latency" reasoning
# ``app.domains.guest.constants.QUOTA_RESET_SWEEP_INTERVAL_SECONDS``'s own
# docstring already establishes for an analogous low-urgency proactive
# cleanup.
PROVISIONING_TOKEN_CLEANUP_SWEEP_INTERVAL_SECONDS = 3600.0

TASK_RUN_STALE_HEARTBEAT_SWEEP = "app.domains.router.tasks.run_stale_heartbeat_sweep"

# Every 60 seconds, which is far more often than any other sweep here, and
# deliberately so. This is the ONLY thing that ever moves a router out of
# ``ONLINE``; until it runs, the platform believes a dead router is alive.
# The threshold it enforces is 15 minutes
# (``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``), so the interval sets how
# much LATER than 15 minutes the truth arrives -- at hourly, a router could
# read online for 75 minutes after it stopped answering, and "offline" would
# mean something different depending on when you looked.
#
# The cost is a single indexed query against ``ix_routers_status`` that in
# the overwhelmingly common case returns nothing and writes nothing. That is
# cheap in a way an hour of a wrong answer is not.
STALE_HEARTBEAT_SWEEP_INTERVAL_SECONDS = 60.0

# ============================================================================
# Router reachability sweep -- the FAST, ALERT-ONLY liveness path.
# See ``service.RouterService.sweep_router_reachability`` and
# ``enums.RouterReachabilityState`` for the full reasoning.
# ============================================================================

TASK_RUN_ROUTER_REACHABILITY_SWEEP = (
    "app.domains.router.tasks.run_router_reachability_sweep"
)

# Every 30 seconds. This is the only cadence in this file chosen by a
# latency budget rather than by cost, so the budget is written out:
#
#   t+0s    the site goes dark.
#   t+<=60s the router misses its next ``/agent/authorized-macs`` poll.
#
#           The 60 seconds is not an assumption. The deployed RouterOS
#           setup script installs two schedulers, and the frontend
#           generator that writes them pins both:
#           ``cloudguest-authmac-sched`` at ``interval=1m`` and
#           ``cloudguest-heartbeat-sched`` at ``interval=5m`` (see
#           ``buildAuthorizedMacStatements``/``buildHeartbeatStatements``
#           in the console repo's ``RouterDetailTabs.tsx``). They were split
#           into separate schedulers for unrelated reasons -- a paste-size
#           ceiling in WinBox and "a broken MAC sync must not stop the
#           router reporting that it is alive" -- and the useful side
#           effect is a liveness signal five times fresher than the
#           heartbeat, which is why absence here is measured against agent
#           CONTACT and never against ``last_seen_at``.
#
#           Both outages on 2026-09-07 bear this out: the authmac poll
#           stopped within a minute of the site going away and resumed a
#           minute before the heartbeat did.
#
#           If that scheduler's interval ever changes, this constant and
#           ROUTER_REACHABILITY_SILENCE_SECONDS below must change with it.
#   t+<=90s this sweep sees contact older than
#           ROUTER_REACHABILITY_SILENCE_SECONDS and records miss #1.
#   t+<=120s miss #2 -> the router is declared UNREACHABLE.
#   t+<=150s ``monitoring``'s alert evaluation sweep (30s) turns that into
#           an ``Alert`` and dispatches the email inline.
#
# Two misses rather than one is not padding: a single missed poll is a
# dropped packet, a 502 during a deploy, or a worker that ran a second
# late. Two consecutive misses over a window we can prove we were awake for
# is the cheapest honest evidence that the site, not the platform, went
# away. The confirmation probe below is what makes it evidence about THEM.
ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS = 30.0

# How long a router may stay silent before one observation counts as a miss.
# 90s = one and a half agent poll intervals: long enough that a single
# late/dropped poll is not a miss, short enough that two misses land inside
# the two-minute budget above.
ROUTER_REACHABILITY_SILENCE_SECONDS = 90

# Consecutive misses required before REACHABLE -> UNREACHABLE.
ROUTER_REACHABILITY_MISSES_TO_ALERT = 2

# Consecutive hits required before UNREACHABLE -> REACHABLE.
#
# This is the flap guard, and it is deliberately asymmetric with the two
# misses above. On 2026-09-07 one router went down at 03:50, came back at
# 04:12, and went down again at 04:16 -- twice in 35 minutes. Resolving on
# the first successful contact would have sent "it's back" at 04:13 and
# "it's down" again at 04:18: four emails for one bad night. Requiring the
# site to stay continuously in touch for ten minutes' worth of polls before
# we call it recovered collapses that whole episode into exactly one "down"
# email and one "back up" email -- and it does so without any separate
# cooldown/suppression table, because the alert simply never closes in
# between, and the Alert Engine's own de-duplication key
# (rule, org, location, router) already refuses to open a second one while
# the first is open.
ROUTER_REACHABILITY_HITS_TO_RESOLVE = 20

# The platform-vs-venue guard, expressed as a fraction of the routers this
# sweep actually evaluated in one pass.
#
# Absence is ambiguous by construction: "we stopped hearing from you" looks
# identical whether the venue lost power or whether OUR api container, OUR
# broker or the WireGuard hub went away. When a majority of an entire fleet
# appears to go silent in the same 30-second window, the overwhelmingly
# likelier explanation is us. In that case the sweep freezes every counter
# untouched, promotes nobody to UNREACHABLE, and says so in one ERROR line
# -- rather than emailing every venue we have. Counters are frozen rather
# than incremented for the same reason the awake-window guard skips a pass
# outright: a window in which the fault was ours is not evidence about
# anybody else, so it must not accumulate toward an alert.
ROUTER_REACHABILITY_FLEET_OUTAGE_RATIO = 0.5

# ...but only once there are enough routers for a "majority" to mean
# anything. With one or two routers deployed, "half the fleet is silent" is
# just "the one real router is down", which is precisely the alert we are
# here to send. Below this size the guard does not apply at all.
ROUTER_REACHABILITY_FLEET_OUTAGE_MIN_ROUTERS = 3

__all__ = [
    "TASK_RUN_PROVISIONING_TOKEN_CLEANUP_SWEEP",
    "PROVISIONING_TOKEN_CLEANUP_SWEEP_INTERVAL_SECONDS",
    "TASK_RUN_STALE_HEARTBEAT_SWEEP",
    "STALE_HEARTBEAT_SWEEP_INTERVAL_SECONDS",
    "TASK_RUN_ROUTER_REACHABILITY_SWEEP",
    "ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS",
    "ROUTER_REACHABILITY_SILENCE_SECONDS",
    "ROUTER_REACHABILITY_MISSES_TO_ALERT",
    "ROUTER_REACHABILITY_HITS_TO_RESOLVE",
    "ROUTER_REACHABILITY_FLEET_OUTAGE_RATIO",
    "ROUTER_REACHABILITY_FLEET_OUTAGE_MIN_ROUTERS",
]

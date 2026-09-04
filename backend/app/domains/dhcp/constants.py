"""Constants for the DHCP Pool Management domain.

``DEFAULT_LEASE_TIME_SECONDS`` is a plain module constant, not a
``Settings``/``Organization.settings`` field -- mirrors
``app.domains.isp.constants``'s own "no new Settings fields" discipline;
per-organization tunability is a real future seam, not implemented in
this first pass.
"""

from __future__ import annotations

from enum import StrEnum

# RouterOS's own default DHCP lease time is 1 day -- used as this domain's
# own default when a caller doesn't supply one.
DEFAULT_LEASE_TIME_SECONDS = 86_400

__all__ = [
    "DEFAULT_LEASE_TIME_SECONDS",
    "DhcpDevicePushStatus",
    "DEVICE_CARRIED_FIELDS",
    "RogueDhcpAlertState",
    "TASK_RUN_ROGUE_DHCP_DETECTION_SWEEP",
    "TASK_DETECT_ROGUE_DHCP_FOR_ROUTER",
    "ROGUE_DHCP_DETECTION_SWEEP_INTERVAL_SECONDS",
    "ROGUE_DHCP_DETECTION_SWEEP_LOCK_REDIS_KEY",
    "ROGUE_DHCP_DETECTION_SWEEP_LOCK_TTL_SECONDS",
]


class DhcpDevicePushStatus(StrEnum):
    """Lifecycle of a :class:`~.models.DhcpPool`'s own device push.

    Distinct from ``is_enabled``, which is intent ("this pool should
    exist"), and independent of ``network_config``'s ``ConfigVersion``
    status -- that pipeline renders a script and ships it over SSH on port
    22, which is filtered on the fleet; this is a direct RouterOS-API push
    on 8728. A pool can be enabled, rendered into a config version, and
    still never have reached a device.

    * ``PENDING`` -- created, never pushed. The state every pre-existing
      row is backfilled to, truthfully: until now no code path could push
      one.
    * ``ACTIVE`` -- a real ``/ip pool`` + ``/ip dhcp-server`` +
      ``/ip dhcp-server network`` triple for this row exists on the router.
    * ``FAILED`` -- the last push attempt raised; ``device_push_error``
      holds the device's own words.
    """

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


# Every column ``DhcpService.push_pool_to_device`` actually puts on the
# router -- the six arguments it hands ``configure_dhcp_pool`` plus the
# ``interface`` both RouterOS identifiers are derived from. Changing any of
# them makes an ``ACTIVE`` row describe leases the device is not handing
# out -- see ``app.common.device_push``.
#
# ``name``/``description`` never leave the database, and ``is_enabled`` is
# intent, not configuration (see ``app.common.device_push``'s own note).
DEVICE_CARRIED_FIELDS = frozenset(
    {
        "interface",
        "address_range_start",
        "address_range_end",
        "gateway_ip_address",
        "dns_primary",
        "dns_secondary",
        "lease_time_seconds",
    }
)


class RogueDhcpAlertState(StrEnum):
    """What the last detection pass learned about one interface's
    ``/ip dhcp-server alert`` row -- the persisted, tri-state form of
    ``wyfy_device_gateway.contract.RogueDhcpAlertStatus``.

    ## Three states, because two would lie

    ``UNKNOWN`` exists so that "we could not reach this router" can never be
    reported as "this router is watching nothing". Those are different
    answers to different questions, and collapsing them is the specific
    mistake this enum is shaped to prevent -- the identical posture
    ``app.domains.monitoring.constants.HealthStatus.UNKNOWN`` already
    documents for its own "exists, but no data to judge from" case, rather
    than a fabricated healthy or a fabricated failure.

    * ``GUARDED`` -- the device answered, and this interface has an alert
      row that is *present and enabled*. Both halves, never just presence:
      RouterOS creates these rows disabled, so presence alone certifies a
      router that is watching nothing (see ``RogueDhcpAlertStatus``'s own
      docstring for the three such rows found on the lab router).
    * ``UNGUARDED`` -- the device answered, and this interface hands out
      addresses with nothing watching it. Reached two ways, and the second
      is the one RouterOS's own default produces: no alert row at all, or a
      row present with ``enabled=False``.
    * ``UNKNOWN`` -- the device did not answer, or answered something we
      could not interpret. ``detail`` carries the reason. This is an
      unanswered question, not a finding.

    ## "Guarded" is this enum's word for *watched*, and nothing more

    ``/ip dhcp-server alert`` logs. It drops nothing, blocks nothing, and
    rate-limits nothing. The value name matches the ``guarded`` property
    the gateway contract already exposes (so the two read as the same
    fact rather than two competing vocabularies), but no operator-facing
    copy derived from this enum may imply prevention -- see
    ``app.domains.readiness.constants``'s ``ROGUE_DHCP_GUARD`` entry, whose
    label and description are deliberately detector-only.
    """

    GUARDED = "guarded"
    UNGUARDED = "unguarded"
    UNKNOWN = "unknown"


# ============================================================================
# Rogue-DHCP detection sweep -- the reader's scheduler
# ============================================================================

# The Beat-scheduled *coordinator*, and the real per-router fan-out leaf
# task it dispatches one of per router. Same two-task shape
# ``app.domains.provisioning_engine.constants
# .TASK_RUN_ROUTER_HEALTH_POLL_SWEEP``/``TASK_POLL_SINGLE_ROUTER_HEALTH``
# already establishes, and for the identical reason: the leaf is a real
# RouterOS API round trip, so one slow router must only ever delay its own
# task.
#
# Deliberately NOT folded into ``poll_single_router_health``. The gateway
# opens a fresh API connection per method
# (``mikrotik_adapter._read_rogue_dhcp_alerts_sync`` calls ``_connect_api``
# itself and closes it in a ``finally``), so there is no connection to
# share and nothing to save by co-locating them. Folding it in would buy
# nothing and cost two things that matter: the health poll -- which runs
# 24x more often than this does -- would get slower, and it would gain a
# new way to fail on a read that has nothing to do with health.
TASK_RUN_ROGUE_DHCP_DETECTION_SWEEP = (
    "app.domains.dhcp.tasks.run_rogue_dhcp_detection_sweep"
)
TASK_DETECT_ROGUE_DHCP_FOR_ROUTER = (
    "app.domains.dhcp.tasks.detect_rogue_dhcp_for_router"
)

# Six hours -- by a wide margin the slowest cadence in this codebase's Beat
# schedule, and deliberately so.
#
# What this sweep reads is *configuration*, not liveness. An
# ``/ip dhcp-server alert`` row does not come and go on its own: it changes
# when this platform pushes a DHCP pool (``DhcpService.push_pool_to_device``
# writes the alert in the same call, so that transition is already known
# without waiting for a sweep), or when a human edits the router directly
# -- an out-of-band event with no deadline attached. Nothing about this
# fact decays on a timescale of minutes.
#
# Against that, the cost is a real RouterOS API round trip per router
# serving DHCP, forever. ``ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS``
# (600s) is right for a signal an operator watches a dashboard for; copying
# it here would multiply this fleet's steady-state device I/O for a fact
# that will read the same at 09:00 and 15:00. Six hours is four reads per
# router per day, which finds a hand-edited router within a working day and
# costs almost nothing.
#
# The readiness checklist never waits on this cadence anyway: it reads the
# persisted row, so its answer is always immediate and always carries
# ``checked_at`` for the reader to judge the row's age themselves.
ROGUE_DHCP_DETECTION_SWEEP_INTERVAL_SECONDS = 21_600.0

# Redis SETNX-style overlap-prevention lock over the *coordinator's* own
# listing+dispatch phase only -- verbatim the contract
# ``app.domains.provisioning_engine.constants
# .ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY`` documents in full. It protects
# against two coordinator invocations racing (Beat restarting mid-tick, a
# manual trigger racing a scheduled one), never against a slow router: a
# slow router only ever delays its own leaf task.
ROGUE_DHCP_DETECTION_SWEEP_LOCK_REDIS_KEY = "dhcp:rogue_dhcp_detection_sweep:lock"

# Crash-safety backstop only -- the coordinator always releases this
# explicitly in a ``finally`` once dispatch completes. Sized for one DB
# query plus N in-memory ``.delay()`` calls, not for the leaf tasks' own
# device I/O; gating release on those would defeat fan-out entirely.
ROGUE_DHCP_DETECTION_SWEEP_LOCK_TTL_SECONDS = 300

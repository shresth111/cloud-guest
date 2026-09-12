"""Enumerations and small constants for the Connected Device Management
domain.

``ConnectionType`` is stored as a plain ``String`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this
codebase documents.

## MAC-OUI vendor lookup: real, deliberately minimal, not authoritative

``OUI_VENDOR_PREFIXES`` maps a MAC address's first three octets (the
IEEE-assigned Organizationally Unique Identifier) to a vendor name.
Confirmed via research that no MAC-OUI lookup exists anywhere in this
codebase before this domain. A complete, authoritative OUI database has
tens of thousands of entries (IEEE's own public registry) -- reproducing
it here would either be a large, unmaintained data dump or an invitation
to silently fabricate vendor names for prefixes this table doesn't
recognize. This starter table is intentionally small and contains only
entries this codebase can state with real confidence (well-documented,
widely-cited OUI blocks), mirroring
``app.domains.guest.models.RadiusNasClient.vendor``'s own "a real, true
default, not a fabricated placeholder" discipline: a MAC prefix that
isn't in this table returns ``None`` (unknown), never a guessed vendor
name. Extending this table with more real, verified OUI entries (or
swapping it for a real OUI database lookup) is a legitimate future seam.
"""

from __future__ import annotations

from enum import StrEnum


class ConnectionType(StrEnum):
    """How a device was observed connecting.

    ``WIRELESS`` iff a vendor adapter reported the device associated to a
    radio the router itself owns. ``WIRED`` iff the adapter could have
    reported that and did not. ``UNKNOWN`` when the router cannot answer
    the question at all.

    **``UNKNOWN`` is the normal value on this fleet, not an error.** Every
    deployed router is a wired hEX lite with no radio, so it can never
    distinguish a guest's phone on the venue Wi-Fi from a laptop on a
    cable -- both reach it through the same bridge port from a
    third-party access point. Recording those as ``WIRED`` would be a
    positive claim the hardware does not support; see
    ``service._connection_type_for``."""

    WIRED = "wired"
    WIRELESS = "wireless"
    UNKNOWN = "unknown"


# Real, IEEE-assigned OUI prefixes this codebase can state with
# confidence -- see module docstring for the "small and honest, not
# comprehensive" scope note. Canonical uppercase colon-separated form.
OUI_VENDOR_PREFIXES: dict[str, str] = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E4:5F:01": "Raspberry Pi Trading Ltd",
}

# Real RouterOS sync parameters -- see device_adapters.py.
DEVICE_SYNC_TIMEOUT_SECONDS = 15

# Celery constants -- see tasks.py.
TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP = (
    "app.domains.connected_devices.tasks.run_connected_device_sync_sweep"
)

# The real per-router fan-out leaf task ``TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP``
# (the Beat-scheduled coordinator) dispatches one of per router, instead of
# syncing every router sequentially, in-process, itself -- see
# ``tasks.sync_single_router_devices``'s own docstring for the full
# scale-readiness write-up (a real DHCP-lease/ARP discovery call per
# router, potentially more expensive than
# ``app.domains.provisioning_engine``'s simple health ping, made the
# original sequential loop's own overrun risk even worse).
TASK_SYNC_SINGLE_ROUTER_DEVICES = (
    "app.domains.connected_devices.tasks.sync_single_router_devices"
)

# Raised from an original 300s (5 minutes): defense in depth, not the real
# fix (fan-out + the lock below is). Slightly more conservative than
# app.domains.provisioning_engine.constants
# .ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS's own 600s, since this sweep's
# real per-router RouterOS call (full DHCP-lease/ARP discovery) is
# potentially heavier than that domain's simple health ping,
# so real-world device-timeout variance deserves a bit more headroom here.
CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS = 900.0

# Redis SETNX-style overlap-prevention lock -- identical shape and identical
# scope to app.domains.provisioning_engine.constants
# .ROUTER_HEALTH_POLL_SWEEP_LOCK_REDIS_KEY's own (guards only the
# coordinator's own listing+dispatch phase, not the fanned-out per-router
# leaf tasks' own independent run times) -- see that constant's own
# docstring for the full "what this protects against, and what it
# deliberately does not" write-up, which applies here unchanged.
CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY = (
    "connected_devices:sync_sweep:lock"
)

# Same reasoning as
# app.domains.provisioning_engine.constants
# .ROUTER_HEALTH_POLL_SWEEP_LOCK_TTL_SECONDS's own identical constant: a
# crash-safety backstop for the coordinator's own quick listing+dispatch
# phase, not a bound on how long any fanned-out leaf task's own device I/O
# may take.
CONNECTED_DEVICE_SYNC_SWEEP_LOCK_TTL_SECONDS = 300

# ============================================================================
# Monitored-hardware liveness sweep -- Celery Beat task wiring.
# ============================================================================

#: The fast, ping-driven sweep that makes a monitored device flip to DOWN
#: within a minute of actually going offline -- instead of waiting out the
#: DHCP lease the router still holds as ``bound`` plus the next
#: CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS discovery tick (see
#: ``service.run_monitored_hardware_liveness_sweep``'s docstring for the
#: full "the discovery sweep cannot see a power-cut AP, only a lease"
#: write-up). The cadence is deliberately close to
#: ``app.domains.isp.constants.ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS``'s
#: own 30s: a venue access point going down is exactly as operationally
#: urgent as a WAN uplink failing, and the sweep's real per-router cost is
#: one RouterOS ping per registered device (handfuls per venue, not the
#: full discovery call), so the sequential-sweep overrun risk the ISP
#: sweep's own docstring documents does not apply at today's scale. The
#: real fleet is a handful of routers today; whoever revisits this once
#: monitored-device count actually grows should apply the same
#: bounded-concurrency/overlap-lock note that sweep's docstring ends with.
MONITORED_HARDWARE_LIVENESS_SWEEP_INTERVAL_SECONDS = 30.0

#: How many ICMP echoes one liveness probe issues per device. 2, not 1: a
#: single dropped packet on a wired link is noise and must not read as a
#: false DOWN. ``0`` of these received is the DOWN verdict -- no extra
#: consecutive-miss guard, per the founder's "ping drop hote hi down
#: dikha do" (a wired venue AP answering 0/2 echoes is down, full stop).
MONITORED_HARDWARE_LIVENESS_PING_COUNT = 2

# Redis SETNX-style overlap-prevention lock for the liveness sweep's
# coordinator phase -- identical shape/scope to
# CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY above.
MONITORED_HARDWARE_LIVENESS_SWEEP_LOCK_REDIS_KEY = (
    "connected_devices:monitored_hardware_liveness:lock"
)

# Crash-safety backstop for the coordinator's own quick listing+dispatch
# phase -- see CONNECTED_DEVICE_SYNC_SWEEP_LOCK_TTL_SECONDS above.
MONITORED_HARDWARE_LIVENESS_SWEEP_LOCK_TTL_SECONDS = 120

#: The Beat-scheduled coordinator task name -- see tasks.py.
TASK_RUN_MONITORED_HARDWARE_LIVENESS_SWEEP = (
    "app.domains.connected_devices.tasks.run_monitored_hardware_liveness_sweep"
)


__all__ = [
    "ConnectionType",
    "OUI_VENDOR_PREFIXES",
    "DEVICE_SYNC_TIMEOUT_SECONDS",
    "TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP",
    "TASK_SYNC_SINGLE_ROUTER_DEVICES",
    "CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS",
    "CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY",
    "CONNECTED_DEVICE_SYNC_SWEEP_LOCK_TTL_SECONDS",
    "MONITORED_HARDWARE_LIVENESS_SWEEP_INTERVAL_SECONDS",
    "MONITORED_HARDWARE_LIVENESS_PING_COUNT",
    "MONITORED_HARDWARE_LIVENESS_SWEEP_LOCK_REDIS_KEY",
    "MONITORED_HARDWARE_LIVENESS_SWEEP_LOCK_TTL_SECONDS",
    "TASK_RUN_MONITORED_HARDWARE_LIVENESS_SWEEP",
]

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
    """How a device was observed connecting -- ``WIRELESS`` iff it
    appears in the router's own wireless registration table, ``WIRED``
    iff seen only via DHCP lease/ARP, ``UNKNOWN`` if the sync couldn't
    determine either (e.g. a stale entry with no fresh data this tick)."""

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
# scale-readiness write-up (a real DHCP-lease/ARP/wireless-registration-
# table discovery call per router, potentially more expensive than
# ``app.domains.provisioning_engine``'s simple health ping, made the
# original sequential loop's own overrun risk even worse).
TASK_SYNC_SINGLE_ROUTER_DEVICES = (
    "app.domains.connected_devices.tasks.sync_single_router_devices"
)

# Raised from an original 300s (5 minutes): defense in depth, not the real
# fix (fan-out + the lock below is). Slightly more conservative than
# app.domains.provisioning_engine.constants
# .ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS's own 600s, since this sweep's
# real per-router RouterOS call (full DHCP-lease/ARP/wireless-registration
# discovery) is potentially heavier than that domain's simple health ping,
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


__all__ = [
    "ConnectionType",
    "OUI_VENDOR_PREFIXES",
    "DEVICE_SYNC_TIMEOUT_SECONDS",
    "TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP",
    "TASK_SYNC_SINGLE_ROUTER_DEVICES",
    "CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS",
    "CONNECTED_DEVICE_SYNC_SWEEP_LOCK_REDIS_KEY",
    "CONNECTED_DEVICE_SYNC_SWEEP_LOCK_TTL_SECONDS",
]

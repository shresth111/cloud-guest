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
# Every 5 minutes -- a connected-device list is operationally visible
# (an admin's live-devices view) but does not need ISP-link-sweep's own
# 60-second cadence (nothing here drives an automatic failover decision
# the way a WAN health check does) -- mirrors
# app.domains.guest.constants.SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS's
# own 5-minute cadence reasoning for an identically "visible, not
# safety-critical" concern.
CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS = 300.0


__all__ = [
    "ConnectionType",
    "OUI_VENDOR_PREFIXES",
    "DEVICE_SYNC_TIMEOUT_SECONDS",
    "TASK_RUN_CONNECTED_DEVICE_SYNC_SWEEP",
    "CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS",
]

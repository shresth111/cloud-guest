"""Enumerations for the Monitored Hardware domain.

Stored as plain ``String`` columns, never native PostgreSQL enum types --
the same reason every other domain in this codebase documents: adding a
new value never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class HardwareType(StrEnum):
    """Matches the frontend's own ``DeviceType`` union exactly (see
    ``cloudguest-foundation/src/stores/deviceStore.ts``) -- this domain's
    whole reason for existing is to give that same set of categories a
    real backend, not a redesigned one."""

    ACCESS_POINT = "Access Point"
    PRINTER = "Printer"
    ROUTER = "Router"
    CAMERA = "Camera"
    OTHER = "Other"


class HardwareStatus(StrEnum):
    """See ``__init__.py``'s own module docstring for the full "derived,
    never fabricated" reasoning behind each of these three states."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


#: How old a connected-device sighting may be before an ``is_active`` row
#: stops meaning "UP". The device-sync sweep refreshes a genuinely live
#: device's ``last_seen_at`` every
#: ``CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS`` (900s, see
#: ``app.domains.connected_devices.constants``), so a row whose last sighting
#: is older than two full sweep periods cannot be a device the uplink router
#: is actually serving right now -- it is a row nobody has been able to
#: refresh (router unreachable, sweep stalled), and deriving "UP" from it
#: would repeat the exact bug this constant exists for: a venue access point
#: that went down kept showing UP because the sync that would have flipped
#: ``is_active`` never ran. Two periods rather than one deliberately
#: tolerates a single dropped sweep (per-router isolation means one
#: unreachable router fails its own tick without affecting the fleet) while
#: still bounding staleness to ~30 minutes.
STALE_SIGHTING_AFTER_SECONDS = 2 * 900 + 60  # two sweeps + a one-minute grace


__all__ = ["HardwareStatus", "HardwareType", "STALE_SIGHTING_AFTER_SECONDS"]

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


class ObservationIssue(StrEnum):
    """Why a device that is not UP has no trustworthy observation -- sent
    beside ``status`` so a screen can say what is actually wrong instead of
    "Never observed".

    ``status`` alone cannot carry this. "unknown" was the answer both for a
    device the router genuinely has not seen and for a device at a venue
    whose router this platform cannot log in to, and the second one reads,
    to the owner looking at a working access point, as the platform
    claiming their hardware is missing.

    ``None`` (no issue) is the ordinary case: the device is UP, or the
    router was read successfully and the verdict stands on its own.
    """

    #: No router at this device's location, so nothing can observe it.
    NO_ROUTER = "no_router"
    #: Every router at the location is controller-managed (e.g. Omada).
    #: This pipeline reads RouterOS DHCP leases, which a controller venue
    #: does not have; its devices are listed from the controller instead.
    CONTROLLER_MANAGED = "controller_managed"
    #: The router has no stored RouterOS API login.
    ROUTER_MISSING_CREDENTIALS = "router_missing_credentials"
    #: The router refused the stored RouterOS API login.
    ROUTER_AUTH_FAILED = "router_auth_failed"
    #: The router could not be connected to.
    ROUTER_UNREACHABLE = "router_unreachable"
    #: The router was connected to but the read failed for another reason.
    ROUTER_READ_FAILED = "router_read_failed"
    #: No discovery read of the router has completed yet (it runs every 15
    #: minutes) -- a device registered a minute ago is waiting, not missing.
    ROUTER_NOT_SYNCED_YET = "router_not_synced_yet"
    #: The router was read successfully and this MAC was not on it. The one
    #: case where "not seen" is the honest answer.
    NOT_SEEN_BY_ROUTER = "not_seen_by_router"


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


__all__ = [
    "HardwareStatus",
    "HardwareType",
    "ObservationIssue",
    "STALE_SIGHTING_AFTER_SECONDS",
]

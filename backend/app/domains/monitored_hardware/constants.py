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


class StatusSource(StrEnum):
    """Whether this platform measures this device's liveness at all.

    Not a fourth :class:`HardwareStatus`. It answers a question that is
    upstream of the status and stays true whatever the status happens to
    be: *does anything here ever look at this device?*

    The failure it exists to stop is the one ``router-vendors.ts``'s
    ``routerLivenessIsMeasured`` already stops one screen over. A
    monitored-hardware row's UP/DOWN is derived from a ``ConnectedDevice``
    row that only two writers ever touch, and both of them reach the venue
    through a RouterOS session: the DHCP-lease discovery sync and the
    ICMP/ARP liveness sweep. At a venue whose network is run by a vendor
    controller there is no RouterOS session to open, so neither writer ever
    runs -- and the row sat at ``unknown`` forever, which on the screen read
    as "we looked and never saw it". Nothing here ever looked.

    ``MEASURED`` therefore means "a probe path exists", not "a probe has
    succeeded". A brand-new row at a MikroTik venue is ``MEASURED`` /
    ``NEVER_OBSERVED`` from the moment it is registered, which is exactly
    the pre-existing meaning of its ``unknown`` status and is why that
    venue's behaviour is unchanged by this field existing.
    """

    MEASURED = "measured"
    UNMEASURED = "unmeasured"


class StatusReason(StrEnum):
    """Why the status is what it is -- a machine-readable code, never prose.

    Prose belongs to the console (``@/lib/device-liveness``), for the same
    reason ``vendor_capabilities.controller_state_for`` gives: a sentence
    composed here would be a second copy of the words, free to drift from
    the ones a customer actually reads.
    """

    #: UP/DOWN derived from a real sighting -- the discovery sync's
    #: ``is_active`` as re-judged by the ICMP/ARP liveness sweep.
    LIVENESS_PROBE = "liveness_probe"
    #: A probe path exists and has never produced a sighting of this MAC.
    #: The pre-existing meaning of ``unknown`` at an agent-managed venue.
    NEVER_OBSERVED = "never_observed"
    #: No probe path exists: the router that would have to run the probe is
    #: reached only through its vendor's controller. See
    #: ``app.domains.router.vendor_capabilities``.
    CONTROLLER_MANAGED = "controller_managed"


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
    "StatusReason",
    "StatusSource",
    "STALE_SIGHTING_AFTER_SECONDS",
]

"""Router Analytics + Network Analytics' "Internet Availability" proxy
signal (BE-012 Part 3).

**This is a documented PROXY signal, not a live internet/uplink probe.**
There is no real MikroTik device, no live ping/traceroute, and no WAN-uplink
telemetry anywhere in this sandbox to check "is this router's internet
uplink actually up" directly -- the same honest "simulated, DB-tracked
signal, not a live daemon reach-out" posture
``app.domains.monitoring.service.MonitoringService.check_freeradius_health``/
``check_wireguard_health`` already document for their own proxy signals
(composing with ``RadiusNasClient``/``GuestSession`` activity and
``WireGuardPeer.last_handshake_at`` respectively, rather than a live
FreeRADIUS/`wg show` reach-out).

## Why ``Router.status == ONLINE`` alone is not enough

``app.domains.router.enums.RouterStatus.ONLINE`` documents itself as "the
device is currently checking in / reachable" -- but nothing in
``app.domains.router`` automatically flips an ``ONLINE`` router to
``OFFLINE`` purely from a missed heartbeat; that transition only happens
the next time something calls ``RouterService.heartbeat`` or an explicit
status-changing endpoint. A router whose last heartbeat was many hours ago
could therefore still read ``status=ONLINE`` in the database even though it
is, in reality, almost certainly not reachable right now. This is exactly
the same gap ``app.domains.monitoring.constants.RouterLifecycleStage``'s own
module docstring documents and ``app.domains.monitoring.validators
.compute_lifecycle_stage`` already resolves for the ZTP dashboard, by
combining ``Router.status`` with ``Router.last_seen_at`` recency rather than
trusting ``status`` alone.

## The exact formula, composed (not reinvented) from monitoring's own threshold

A router is reported ``internet_available=True`` here if and only if:

1. ``Router.status == RouterStatus.ONLINE``, **and**
2. ``Router.last_seen_at`` is not ``None`` and is no more than
   ``app.domains.monitoring.constants.ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``
   old (the exact same constant ``compute_lifecycle_stage`` itself uses for
   its own ``ONLINE -> OFFLINE`` staleness rule -- reused directly, not
   re-derived as a new, possibly-inconsistent number).

Anything else (``status`` not ``ONLINE``, or a heartbeat older than the
threshold, or a router that has never once checked in at all) is reported
``internet_available=False``. This is a boolean simplification of
``compute_lifecycle_stage``'s own richer 9-state vocabulary (which also
accounts for provisioning/enrollment/suspension states this module has no
need to distinguish for a plain "is this router's internet connectivity
proxy currently healthy" signal) -- reusing that module's own staleness
threshold keeps the two dashboards' notion of "stale" in lockstep without
importing its heavier ZTP-specific machinery (``RouterEnrollmentRequest``/
``ProvisioningJob`` lookups) this module does not otherwise touch.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.domains.monitoring.constants import ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES
from app.domains.router.enums import RouterStatus


def compute_internet_availability(
    *,
    status: str,
    last_seen_at: datetime | None,
    now: datetime | None = None,
) -> bool:
    """Returns the Internet Availability proxy signal for one router -- see
    module docstring for the exact formula and reasoning."""
    if status != RouterStatus.ONLINE.value:
        return False
    if last_seen_at is None:
        return False
    moment = now or datetime.now(UTC)
    staleness = moment - last_seen_at
    return staleness <= timedelta(minutes=ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES)


__all__ = ["compute_internet_availability"]

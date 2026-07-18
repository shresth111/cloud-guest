"""Enumerations for the Router domain.

Stored as plain ``String`` columns on the ORM models (mirroring every other
domain's documented convention -- e.g. ``app.domains.location.enums``'s
module docstring) rather than native PostgreSQL enum types, so adding a new
value never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class RouterStatus(StrEnum):
    """Lifecycle status of a Router device record.

    Deliberately **not** a copy of ``OrganizationStatus``/``LocationStatus``
    (``active``/``suspended``/``archived``) -- a physical device has a
    materially different lifecycle: it must be provisioned before it can
    ever be "active", and its online/offline state is derived from
    heartbeats rather than an administrative toggle. See
    ``docs/router/ROUTER_ARCHITECTURE.md`` §2 for the full state-transition
    diagram; the short version:

    * ``PENDING_PROVISIONING`` -- the device record has been created (serial
      number, MAC address, model on file) but the physical device has not
      yet authenticated with a provisioning token. This is the only state a
      newly-registered router starts in.
    * ``PROVISIONING`` -- the device has presented a valid provisioning
      token at the check-in endpoint (consuming it) and initial
      configuration is in progress. Not yet serving guest traffic.
    * ``ONLINE`` -- provisioning completed successfully and the device is
      currently checking in / reachable. The only status that reflects
      "healthy and current" at a glance.
    * ``OFFLINE`` -- was previously ``ONLINE`` but missed its expected
      heartbeat/health check. Purely a connectivity signal, not an
      administrative action -- nothing routes a device into or out of this
      state except the heartbeat/check-in flow itself.
    * ``SUSPENDED`` -- administratively disabled (e.g. non-payment, policy
      violation), independent of the device's actual connectivity. Only the
      dedicated ``suspend``/``reinstate`` endpoints transition into or out
      of this state.
    * ``DECOMMISSIONED`` -- permanently retired. Terminal: paired with
      ``BaseModel``'s soft-delete mixin (``RouterService.decommission``
      both sets this status and soft-deletes the row), never transitioned
      out of.
    """

    PENDING_PROVISIONING = "pending_provisioning"
    PROVISIONING = "provisioning"
    ONLINE = "online"
    OFFLINE = "offline"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


# The explicit, exhaustive legal-transition graph -- any status change not
# listed here is rejected by ``RouterService`` with
# ``InvalidRouterStatusTransitionError``. See
# ``docs/router/ROUTER_ARCHITECTURE.md`` §2 for the reasoning behind each
# edge (in particular: why ``PROVISIONING -> ONLINE`` is a direct, explicit
# edge but ``SUSPENDED -> (reinstate)`` lands on ``OFFLINE`` rather than
# ``ONLINE``, since only a heartbeat/check-in may ever assert "currently
# reachable").
ROUTER_STATUS_TRANSITIONS: dict[RouterStatus, frozenset[RouterStatus]] = {
    RouterStatus.PENDING_PROVISIONING: frozenset(
        {RouterStatus.PROVISIONING, RouterStatus.DECOMMISSIONED}
    ),
    RouterStatus.PROVISIONING: frozenset(
        {RouterStatus.ONLINE, RouterStatus.DECOMMISSIONED}
    ),
    RouterStatus.ONLINE: frozenset(
        {RouterStatus.OFFLINE, RouterStatus.SUSPENDED, RouterStatus.DECOMMISSIONED}
    ),
    RouterStatus.OFFLINE: frozenset(
        {RouterStatus.ONLINE, RouterStatus.SUSPENDED, RouterStatus.DECOMMISSIONED}
    ),
    RouterStatus.SUSPENDED: frozenset(
        {RouterStatus.OFFLINE, RouterStatus.DECOMMISSIONED}
    ),
    RouterStatus.DECOMMISSIONED: frozenset(),
}


class RouterHealthStatus(StrEnum):
    """A minimal, non-persisted-metrics health signal for the device-list
    view -- "is this router currently reachable", not a metrics/telemetry
    system (that is the separate, already-seeded ``Monitoring``/``Alerts``
    permission modules' job, a future domain). ``Router.health_status`` is
    ``None`` until the first health check ever runs (meaning "unknown", not
    stored as its own enum value -- see ``docs/router/ROUTER_ARCHITECTURE.md``
    §4)."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"

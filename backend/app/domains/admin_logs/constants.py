"""Real, documented bounds and error-classification for the Admin Logs
domain -- the same "never a silent, unbounded fetch" posture
``app.domains.controller_logs.constants``'s own
``MAX_PROVISION_JOBS_FOR_LOG_MERGE`` already establishes for its own
in-memory merge."""

from __future__ import annotations

from app.domains.router_provisioning.constants import RouterEventType

# Real, bounded fan-out for the Router Logs merge: at most this many of
# an organization's own locations, at most this many routers per
# location, and at most this many recent events per router are fetched
# before merging/sorting/paginating in Python (mirrors
# app.domains.controller_logs's own bounded-merge precedent for Provision
# Logs). A location/router count beyond these ceilings simply means the
# oldest locations/routers (by list ordering) are excluded from this
# merge, never a silent truncation of any one router's own event history.
MAX_LOCATIONS_FOR_ROUTER_LOG_MERGE = 50
MAX_ROUTERS_PER_LOCATION_FOR_ROUTER_LOG_MERGE = 50
MAX_EVENTS_PER_ROUTER_FOR_ROUTER_LOG_MERGE = 25

# Which real RouterEventType values represent a genuine failure -- drives
# the "what errors are there" framing on the customer-facing Router Logs
# section. Every other event type (enrollment submitted/approved, config
# drafted/applied, backups, restores/resets that *completed*, secret
# rotation, health snapshots) is a normal, non-error lifecycle event.
ERROR_EVENT_TYPES = frozenset(
    {
        RouterEventType.ENROLLMENT_REJECTED.value,
        RouterEventType.CONFIG_APPLY_FAILED.value,
        RouterEventType.RESTORE_FAILED.value,
        RouterEventType.FACTORY_RESET_FAILED.value,
    }
)

__all__ = [
    "MAX_LOCATIONS_FOR_ROUTER_LOG_MERGE",
    "MAX_ROUTERS_PER_LOCATION_FOR_ROUTER_LOG_MERGE",
    "MAX_EVENTS_PER_ROUTER_FOR_ROUTER_LOG_MERGE",
    "ERROR_EVENT_TYPES",
]

"""Enumerations and small constants for the Monitoring domain (BE-011 Part 1:
Health Engine + Event Engine).

Stored as plain ``String`` columns on the ORM models (mirroring every other
domain's own convention -- e.g. ``app.domains.router.enums``,
``app.domains.guest.constants``), never native PostgreSQL enum types, so
adding a new value never requires an ``ALTER TYPE`` migration.

**No new ``Settings`` fields.** Like ``app.domains.guest``/
``app.domains.wireguard`` (partially), every tunable threshold this module
needs (storage usage thresholds, FreeRADIUS activity staleness) lives here
as a plain module constant rather than growing ``app.core.config.Settings``
-- this module's directory rule keeps ``app/core/config.py`` untouched.
"""

from __future__ import annotations

from enum import StrEnum

# ============================================================================
# Health Engine
# ============================================================================


class HealthComponent(StrEnum):
    """The fixed, closed set of platform-level (not per-router) components
    the Health Engine checks.

    Deliberately excludes anything router-specific -- device/router health
    stays entirely in ``app.domains.router.models.Router.health_status``/
    ``last_seen_at``/``last_health_check_at`` and
    ``app.domains.router_provisioning.models.RouterHealthSnapshot``/
    ``RouterEvent`` (BE-008/BE-009). See ``models.py``'s module docstring for
    the full "why no ``DeviceHealth`` table" write-up.

    ``CELERY``/``WEBSOCKET`` are real, first-class enum members even though
    neither piece of infrastructure exists in this codebase yet (no Celery
    worker/broker anywhere, no WebSocket support anywhere) -- per this
    module's honesty mandate, a health-check *type* is defined and wired
    into every dashboard/history endpoint now, so no migration is needed
    once a real deployment exists; ``service.py``'s
    ``check_celery_health``/``check_websocket_health`` return an honest
    ``HealthStatus.UNKNOWN`` with a documented reason, never a fabricated
    ``HEALTHY``.
    """

    DATABASE = "database"
    REDIS = "redis"
    API = "api"
    AUTH = "auth"
    STORAGE = "storage"
    CELERY = "celery"
    WEBSOCKET = "websocket"
    FREERADIUS = "freeradius"
    WIREGUARD = "wireguard"


class HealthStatus(StrEnum):
    """The result of a single health check, or a component's current rolled-
    up state (``ServiceHealth.status``).

    ``UNKNOWN`` covers two genuinely distinct situations, both legitimate:
    (a) infrastructure that does not exist yet in this environment
    (``CELERY``/``WEBSOCKET`` -- see ``HealthComponent``'s docstring), and
    (b) a component that exists but currently has no data to judge from
    (e.g. ``FREERADIUS`` before any NAS client has ever registered,
    ``WIREGUARD`` before any tunnel has ever been provisioned). Neither case
    is a fabricated ``HEALTHY``.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# Storage health thresholds (``shutil.disk_usage`` against
# ``Settings.log_dir``) -- percentage of the filesystem's total bytes
# reported as "used" at which storage health degrades/turns unhealthy. Fairly
# conservative (85%/95%) since a full log volume silently breaks structured
# logging (``app.core.logging``) for every domain, not just this one.
STORAGE_DEGRADED_USED_PERCENT = 85.0
STORAGE_UNHEALTHY_USED_PERCENT = 95.0

# How long since the most recent guest RADIUS-accounting-driven session
# activity (``GuestSession.last_activity_at``) before the FreeRADIUS proxy
# signal degrades from HEALTHY -- see ``service.py``'s
# ``check_freeradius_health`` module docstring for why this is a proxy
# signal, not a live daemon ping. Deliberately generous (an hour) since
# guest WiFi traffic is naturally bursty (e.g. overnight at a hotel), unlike
# WireGuard's much tighter keepalive-driven staleness window.
FREERADIUS_ACTIVITY_STALE_MINUTES = 60

# ============================================================================
# Heartbeat Log (cross-domain, platform-wide -- see models.py)
# ============================================================================


class HeartbeatComponentType(StrEnum):
    """The kind of thing a :class:`~.models.HeartbeatLog` row's
    ``component_id`` polymorphically refers to -- see that model's module
    docstring for the full polymorphic-reference design write-up.

    * ``ROUTER`` -- ``component_id`` is a ``routers.id``. Populated by an
      additive hook in ``app.domains.router_agent.router.agent_heartbeat``
      (see that module's own updated docstring) alongside BE-008's existing
      ``Router.last_seen_at`` update -- this table is a platform-wide,
      cross-component *log* of that same event, not a replacement for it.
    * ``WIREGUARD_PEER`` -- ``component_id`` is a ``wireguard_peers.id``.
      Defined and ready, but nothing currently writes it: the natural
      seam (``WireGuardService.record_handshake``) lives inside
      ``app.domains.wireguard``, which this module's directory rule does
      not permit editing in this iteration (only one such additive hook was
      budgeted, spent on the router-agent seam above, which reaches far
      more devices). A future BE-011 part may add this the same way.
    * ``SERVICE`` -- ``component_id`` is any platform-service's own stable
      identifier (not a foreign key into any existing table -- e.g. a
      worker/daemon process that self-registers). Reserved for a future
      platform self-heartbeat source (a Celery worker, once one exists, or
      a scheduled sweep process) -- nothing in this codebase emits one yet
      (there is no background task runner at all, see the Celery honesty
      note above), so this value currently has no live writer either, the
      same honest "defined, not fabricated" posture as ``HealthComponent
      .CELERY``.
    """

    ROUTER = "router"
    WIREGUARD_PEER = "wireguard_peer"
    SERVICE = "service"


# ============================================================================
# Event Engine
# ============================================================================


class EventCategory(StrEnum):
    """The cross-domain classification of a timeline entry
    (:class:`~.models.PlatformEvent` or a merged read-side row -- see
    ``service.get_event_timeline``)."""

    SYSTEM = "system"
    SECURITY = "security"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PROVISIONING = "provisioning"
    GUEST = "guest"
    AUDIT = "audit"


class EventSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ``event_type`` values this module's own Health Engine writes onto
# ``PlatformEvent`` when a component's rolled-up status changes (see
# ``service.py``'s ``_record_transition_event``) -- namespaced strings, not
# an exhaustive enum, since ``PlatformEvent.event_type`` is deliberately a
# free-form namespaced string (every domain that ever calls into this
# module's own event recording picks its own, e.g. "router
# .provisioning_failed") rather than a closed set that would need a
# migration for every new domain-specific moment.
EVENT_TYPE_COMPONENT_DEGRADED = "monitoring.component_degraded"
EVENT_TYPE_COMPONENT_UNHEALTHY = "monitoring.component_unhealthy"
EVENT_TYPE_COMPONENT_RECOVERED = "monitoring.component_recovered"

# ``PlatformEvent.source_domain`` value this module stamps on its own
# self-generated health-transition events.
SOURCE_DOMAIN = "monitoring"

# The ``source_domain``/category this module assigns to read-side-merged
# rows from other domains' own tables (``AuditLogEntry``/``RouterEvent``) --
# see ``service.py``'s ``TimelineEntry.from_audit_log``/``from_router_event``.
AUDIT_LOG_SOURCE_DOMAIN = "rbac"
ROUTER_EVENT_SOURCE_DOMAIN = "router_provisioning"

DEFAULT_EVENT_TIMELINE_LIMIT = 100
MAX_EVENT_TIMELINE_LIMIT = 500

DEFAULT_HEALTH_HISTORY_PAGE = 1
DEFAULT_HEALTH_HISTORY_PAGE_SIZE = 25

__all__ = [
    "HealthComponent",
    "HealthStatus",
    "STORAGE_DEGRADED_USED_PERCENT",
    "STORAGE_UNHEALTHY_USED_PERCENT",
    "FREERADIUS_ACTIVITY_STALE_MINUTES",
    "HeartbeatComponentType",
    "EventCategory",
    "EventSeverity",
    "EVENT_TYPE_COMPONENT_DEGRADED",
    "EVENT_TYPE_COMPONENT_UNHEALTHY",
    "EVENT_TYPE_COMPONENT_RECOVERED",
    "SOURCE_DOMAIN",
    "AUDIT_LOG_SOURCE_DOMAIN",
    "ROUTER_EVENT_SOURCE_DOMAIN",
    "DEFAULT_EVENT_TIMELINE_LIMIT",
    "MAX_EVENT_TIMELINE_LIMIT",
    "DEFAULT_HEALTH_HISTORY_PAGE",
    "DEFAULT_HEALTH_HISTORY_PAGE_SIZE",
]

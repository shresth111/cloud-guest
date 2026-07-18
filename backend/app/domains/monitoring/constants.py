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

DEFAULT_LIST_PAGE = 1
DEFAULT_LIST_PAGE_SIZE = 25

# ============================================================================
# Alert Engine (BE-011 Part 2)
# ============================================================================


class AlertTriggerType(StrEnum):
    """The kind of condition an :class:`~.models.AlertRule` watches for.

    * ``HEALTH_STATUS_CHANGE`` -- e.g. "Database Down"/"Router Offline".
      ``AlertRule.target_component`` is either a ``HealthComponent`` value
      (watches the platform-wide ``ServiceHealth`` rollup for that
      component -- composes with Part 1's Health Engine, never duplicates
      it) or the sentinel :data:`ALERT_TARGET_ROUTER` (watches every
      in-scope ``app.domains.router.models.Router.health_status`` directly
      -- read-only, composes with BE-008, the same "read another domain's
      table directly" precedent ``repository.py`` already establishes for
      ``RadiusNasClient``/``WireGuardPeer``/``RouterEvent``).
      ``condition_config`` shape: ``{"expected_status": <str>}``.
    * ``THRESHOLD`` -- e.g. "CPU High"/"Disk Full". Compares one of
      ``app.domains.router_provisioning.models.RouterHealthSnapshot``'s own
      already-persisted metrics (:class:`ThresholdMetric` -- never a new
      metrics system) against a configured value for every router in scope.
      ``AlertRule.target_component`` is always ``None`` for this trigger
      type (the rule watches every router in ``organization_id``'s scope,
      not one named component). ``condition_config`` shape:
      ``{"metric": <ThresholdMetric>, "operator": <ThresholdOperator>,
      "value": <float>}``.
    * ``EVENT_OCCURRED`` -- e.g. "Provisioning Failed"/"Guest Authentication
      Failed"/"OTP Delivery Failed" in the module brief's examples. This
      module can only evaluate a rule against a *queryable* event source,
      and per Part 1's own documented design, the only cross-domain event
      table this module may read without editing another domain's files is
      ``PlatformEvent`` (Part 1's own narrowly-scoped table -- see
      ``models.PlatformEvent``'s docstring). ``RouterEvent``/RBAC's
      ``audit_log_entries`` are deliberately **not** wired as
      ``EVENT_OCCURRED`` sources in this iteration: unlike ``PlatformEvent``,
      ``Alert.related_event_id`` is a single FK to ``platform_events.id``
      (not a polymorphic reference), so matching+de-duplicating against a
      second table's primary key would need a second, differently-typed FK
      column for zero currently-demonstrated need. A genuinely new event
      (e.g. a real "OTP delivery failed" moment) becomes alertable the
      moment its owning domain calls
      ``MonitoringService.record_platform_event`` -- the same composition
      seam Part 1's own docstring already invites -- without any change
      here. ``condition_config`` shape: ``{"event_type": <str>}`` (matches
      ``PlatformEvent.event_type``).
    """

    HEALTH_STATUS_CHANGE = "health_status_change"
    THRESHOLD = "threshold"
    EVENT_OCCURRED = "event_occurred"


# Sentinel ``AlertRule.target_component`` value for a ``HEALTH_STATUS_CHANGE``
# rule that watches per-router ``Router.health_status``
# (``app.domains.router.enums.RouterHealthStatus``) rather than one of this
# module's own platform ``HealthComponent`` values. Deliberately not a
# ``HealthComponent`` member itself -- "router" is not a platform component
# this module's own Health Engine checks (see ``HealthComponent``'s
# docstring), it is a pointer to a *different* domain's own health signal.
ALERT_TARGET_ROUTER = "router"


class ThresholdMetric(StrEnum):
    """The exact, already-persisted
    ``app.domains.router_provisioning.models.RouterHealthSnapshot`` columns a
    ``THRESHOLD`` rule may compare against -- composition, not a new metrics
    system (see ``AlertTriggerType.THRESHOLD``'s docstring)."""

    CPU_USAGE_PERCENT = "cpu_usage_percent"
    MEMORY_USAGE_PERCENT = "memory_usage_percent"
    UPTIME_SECONDS = "uptime_seconds"
    CONNECTED_CLIENTS_COUNT = "connected_clients_count"


class ThresholdOperator(StrEnum):
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EQ = "eq"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """See ``ALERT_STATUS_TRANSITIONS`` for the exact transition graph.

    * ``TRIGGERED`` -- the initial state every ``Alert`` is created in.
    * ``ACKNOWLEDGED`` -- a human has seen it and is working it; set by
      ``POST /alerts/{id}/acknowledge``.
    * ``RESOLVED`` -- terminal. Set either by a human
      (``POST /alerts/{id}/resolve``) or automatically by
      ``AlertService.evaluate_alert_rules`` the moment the underlying
      condition clears (see that method's own docstring for the full
      recovery-design write-up: there is no separate "Router Online" rule,
      recovery is the same rule transitioning its own open alert to
      ``RESOLVED`` plus a recovery notification through the same channels).
    """

    TRIGGERED = "triggered"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


ALERT_STATUS_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.TRIGGERED: frozenset({AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED}),
    AlertStatus.ACKNOWLEDGED: frozenset({AlertStatus.RESOLVED}),
    AlertStatus.RESOLVED: frozenset(),
}

# How far back ``AlertService._evaluate_event_occurred_rule`` looks for
# ``PlatformEvent`` rows matching an ``EVENT_OCCURRED`` rule's
# ``condition_config["event_type"]`` on each evaluation pass. Since this
# environment has no recurring scheduler (no Celery -- see
# ``HealthComponent.CELERY``'s docstring), ``evaluate_alert_rules`` runs
# on-demand (an admin/operator action or a composed call after a health
# check), not on a guaranteed fixed cadence -- a bounded lookback window
# (rather than "since the last evaluation ever ran", which this module has
# no durable checkpoint for) is what keeps repeated evaluation idempotent
# (de-duplicated by ``related_event_id``, see ``Alert``'s module docstring)
# without needing a new "last evaluated at" table.
ALERT_EVENT_LOOKBACK_MINUTES = 15

# ============================================================================
# Notification Engine (BE-011 Part 2)
# ============================================================================


class NotificationChannelType(StrEnum):
    """See ``docs/monitoring/FLOW.md`` for the exact per-type
    ``config_encrypted`` JSON schema and delivery-implementation write-up.

    ``EMAIL``/``SMS`` wrap ``app.domains.otp``'s existing
    ``EmailProviderProtocol``/``SmsProviderProtocol`` (composition, never a
    second provider abstraction). ``SLACK``/``TEAMS``/``DISCORD``/``WEBHOOK``
    are REAL ``httpx.AsyncClient`` POSTs to a configurable incoming-webhook
    URL. ``WHATSAPP`` is an honest logging-only placeholder, mirroring
    OTP's own ``LoggingSmsProvider``/``LoggingEmailProvider`` precedent --
    see ``service.py``'s ``WhatsAppNotifier`` docstring for exactly why this
    one channel (and only this one) does not get a real integration: it
    genuinely requires a paid WhatsApp Business API account/SDK this sandbox
    does not have, unlike Slack/Teams/Discord/Webhook, which are just a
    plain outbound HTTP POST to a URL any operator can generate for free.
    """

    EMAIL = "email"
    SMS = "sms"
    WHATSAPP = "whatsapp"
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    WEBHOOK = "webhook"


class NotificationStatus(StrEnum):
    SENT = "sent"
    FAILED = "failed"


# Timeout for every real outbound HTTP POST this module makes (Slack/Teams/
# Discord/generic Webhook notifiers) -- bounded so one slow/unreachable
# third-party webhook endpoint cannot hang alert dispatch indefinitely.
HTTP_NOTIFICATION_TIMEOUT_SECONDS = 10.0

# ============================================================================
# Incident Engine (BE-011 Part 2)
# ============================================================================


class IncidentStatus(StrEnum):
    """See ``INCIDENT_STATUS_TRANSITIONS`` for the exact transition graph.
    ``OPEN`` is the initial state every ``Incident`` is created in;
    ``CLOSED`` is terminal."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


INCIDENT_STATUS_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.CLOSED}
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {IncidentStatus.OPEN, IncidentStatus.RESOLVED, IncidentStatus.CLOSED}
    ),
    IncidentStatus.RESOLVED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED}
    ),
    IncidentStatus.CLOSED: frozenset(),
}

# ============================================================================
# SLA Monitoring (BE-011 Part 2)
# ============================================================================

DEFAULT_SLA_TARGET_PERCENTAGE = 99.9
DEFAULT_SLA_MEASUREMENT_WINDOW_DAYS = 30

# ============================================================================
# Real-Time (WebSocket + Redis pub/sub) -- BE-011 Part 3
# ============================================================================

# The single Redis pub/sub channel every real-time-producing write path
# (Health Engine status transitions, Alert Engine trigger/resolve, the
# guest-session-start hook) publishes to, and every WebSocket connection
# (``router.py``'s ``/monitoring/ws/dashboard``/``/monitoring/ws/sessions``)
# subscribes to. One shared channel, not one channel per message type --
# see ``router.py``'s module docstring for the full "one channel, two
# purpose-filtered endpoints" design write-up.
MONITORING_LIVE_CHANNEL = "monitoring:live"


class RealtimeMessageType(StrEnum):
    """The closed set of ``"type"`` values a message published to
    :data:`MONITORING_LIVE_CHANNEL` carries -- each WebSocket endpoint
    filters the shared channel down to the subset it cares about (see
    ``router.py``'s ``_DASHBOARD_MESSAGE_TYPES``/``_SESSION_MESSAGE_TYPES``).

    ``GUEST_SESSION_ENDED`` is a real, first-class member with **no current
    writer** -- the same honest "defined, wired into every consumer, not yet
    produced" posture ``HeartbeatComponentType.WIREGUARD_PEER``/
    ``HealthComponent.CELERY`` already establish in this module. Producing
    it would require a hook into ``GuestService``'s session-end methods
    (disconnect/terminate/expire), which this part's directory rule does not
    license (exactly one guest-domain hook was budgeted, spent on the
    login-start seam -- see ``app.domains.guest.service.GuestService``'s
    updated docstring). A future part may add that hook the same way.
    """

    HEALTH_TRANSITION = "health_transition"
    ALERT_TRIGGERED = "alert_triggered"
    ALERT_RESOLVED = "alert_resolved"
    GUEST_SESSION_STARTED = "guest_session_started"
    GUEST_SESSION_ENDED = "guest_session_ended"


# ============================================================================
# ZTP Monitoring Dashboard -- router lifecycle stage (BE-011 Part 3)
# ============================================================================


class RouterLifecycleStage(StrEnum):
    """A **derived, presentation-layer** label synthesizing
    ``app.domains.router_provisioning.constants.EnrollmentStatus`` +
    ``app.domains.router.enums.RouterStatus`` +
    ``app.domains.router_provisioning.constants.ProvisioningJobStatus`` (plus
    heartbeat staleness) into the module brief's idealized 9-state ZTP
    dashboard vocabulary. See
    ``validators.compute_lifecycle_stage`` for the full, exact mapping table
    and ``docs/monitoring/FLOW.md`` for the write-up of why this is computed
    fresh on every read rather than persisted anywhere: every one of its
    inputs already has its own authoritative, independently-owned column in
    its own domain (``RouterEnrollmentRequest.status``, ``Router.status``,
    ``ProvisioningJob.status``/``attempts``, ``Router.last_seen_at``) --
    storing a tenth, derived copy would create a second source of truth that
    can drift the moment any one of those four inputs changes without this
    label being recomputed in lockstep, for a value that costs nothing to
    recompute on read.
    """

    PENDING = "pending"
    CLAIMED = "claimed"
    APPROVED = "approved"
    PROVISIONING = "provisioning"
    PROVISIONED = "provisioned"
    ONLINE = "online"
    OFFLINE = "offline"
    WARNING = "warning"
    FAILED = "failed"


# How long since ``Router.last_seen_at`` before an ``ONLINE`` router's
# lifecycle stage degrades to ``WARNING`` (heartbeat getting stale) and then
# ``OFFLINE`` (heartbeat long gone) -- see ``validators.compute_lifecycle_stage``.
# Mirrors ``Settings.wireguard_handshake_stale_after_minutes``'s identical
# "roughly double the expected keepalive cadence" reasoning for the WARNING
# threshold; OFFLINE is set more generously (three missed heartbeats' worth)
# since a single delayed check-in should read as "degrading", not instantly
# "down".
ROUTER_HEARTBEAT_WARNING_STALE_MINUTES = 5
ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES = 15

DEFAULT_ZTP_PAGE = 1
DEFAULT_ZTP_PAGE_SIZE = 25
DEFAULT_FAILURE_SAMPLE_LIMIT = 5

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
    "DEFAULT_LIST_PAGE",
    "DEFAULT_LIST_PAGE_SIZE",
    "AlertTriggerType",
    "ALERT_TARGET_ROUTER",
    "ThresholdMetric",
    "ThresholdOperator",
    "AlertSeverity",
    "AlertStatus",
    "ALERT_STATUS_TRANSITIONS",
    "ALERT_EVENT_LOOKBACK_MINUTES",
    "NotificationChannelType",
    "NotificationStatus",
    "HTTP_NOTIFICATION_TIMEOUT_SECONDS",
    "IncidentStatus",
    "INCIDENT_STATUS_TRANSITIONS",
    "DEFAULT_SLA_TARGET_PERCENTAGE",
    "DEFAULT_SLA_MEASUREMENT_WINDOW_DAYS",
    "MONITORING_LIVE_CHANNEL",
    "RealtimeMessageType",
    "RouterLifecycleStage",
    "ROUTER_HEARTBEAT_WARNING_STALE_MINUTES",
    "ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES",
    "DEFAULT_ZTP_PAGE",
    "DEFAULT_ZTP_PAGE_SIZE",
    "DEFAULT_FAILURE_SAMPLE_LIMIT",
]

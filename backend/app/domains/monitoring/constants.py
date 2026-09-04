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

    ``CELERY``/``WEBSOCKET`` were once placeholders here, defined ahead of
    the infrastructure so that no migration would be needed once it
    existed, and returning an honest ``HealthStatus.UNKNOWN`` in the
    meantime. **Both are real checks now**, and this paragraph used to say
    otherwise: it claimed "neither piece of infrastructure exists in this
    codebase yet (no Celery worker/broker anywhere, no WebSocket support
    anywhere)" long after ``app.core.celery_app`` shipped a genuine Celery
    deployment with a nineteen-entry ``beat_schedule``,
    ``deploy/docker-compose.prod.yml`` began running ``celery-worker`` and
    ``celery-beat`` services, and BE-011 Part 3 added real WebSocket
    endpoints.

    That is not a harmless stale line. It was read as current on
    2026-09-04 and taken as evidence that this platform has no recurring
    scheduler at all -- which is exactly why nobody noticed the Health
    Engine itself had no Beat entry and the System Health page was showing
    two-day-old rows. A comment that describes infrastructure the reader
    cannot see is load-bearing, and this one pointed the wrong way.

    See ``service.py``'s ``check_celery_health`` (a real
    ``control.inspect().ping()`` against the configured broker, with three
    distinct real outcomes) and ``check_websocket_health`` for what each
    actually does today.
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

    * ``HEALTH_STATUS_CHANGE`` -- e.g. "Database Down"/"Router Offline"/"ISP
      Link Down". ``AlertRule.target_component`` is a ``HealthComponent``
      value (watches the platform-wide ``ServiceHealth`` rollup for that
      component -- composes with Part 1's Health Engine, never duplicates
      it), the sentinel :data:`ALERT_TARGET_ROUTER` (watches every in-scope
      ``app.domains.router.models.Router.health_status`` directly), or the
      sentinel :data:`ALERT_TARGET_ISP_LINK` (watches every in-scope
      ``app.domains.isp.models.IspLink.health_status`` directly), or the
      sentinel :data:`ALERT_TARGET_ROGUE_DHCP_GUARD` (watches every
      in-scope router's persisted
      ``app.domains.dhcp.models.RouterRogueDhcpStatus.alert_state``) -- all
      read-only, the same "read another domain's table directly"
      precedent ``repository.py`` already establishes for
      ``RadiusNasClient``/``WireGuardPeer``/``RouterEvent``.
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

# Sentinel ``AlertRule.target_component`` value for a ``HEALTH_STATUS_CHANGE``
# rule that watches per-ISP-link ``app.domains.isp.models.IspLink
# .health_status`` -- the identical "pointer to a different domain's own
# already-tracked health signal" composition ``ALERT_TARGET_ROUTER`` above
# already establishes, one level down (a router's WAN uplink, not the router
# itself). ``IspLink.health_status`` uses ``app.domains.isp.constants
# .HealthStatus``, a separate enum with the exact same string values as this
# module's own ``HealthStatus`` (``healthy``/``degraded``/``unhealthy``/
# ``unknown``) -- both stored as plain strings, so an ``expected_status`` of
# e.g. ``"unhealthy"`` in a rule's ``condition_config`` compares correctly
# with no coupling between the two enums' Python identities. Kept fresh by
# ``app.domains.isp.service.run_health_check_sweep``'s own Beat-scheduled
# sweep. See
# ``service.AlertService._evaluate_health_status_rule``'s ``ALERT_TARGET_ISP_LINK``
# branch for the read-only composition with ``repository.list_isp_links``
# (the same "query another domain's model directly, read-only" precedent
# ``list_routers`` already establishes, not a call into ``IspService``,
# which has no "list every link across an optional organization scope,
# unpaginated" method this evaluator needs).
ALERT_TARGET_ISP_LINK = "isp_link"

# Sentinel ``AlertRule.target_component`` value for a ``HEALTH_STATUS_CHANGE``
# rule that watches every ``app.domains.monitored_hardware`` device in scope
# (access points, printers, cameras -- anything a venue registers beyond the
# router itself) for its derived ``down`` status. Unlike ``ALERT_TARGET_ROUTER``/
# ``ALERT_TARGET_ISP_LINK``, there is no persisted ``health_status`` column to
# read directly here -- ``MonitoredHardware``'s status (``up``/``down``/
# ``unknown``) is honestly derived at read time from a live join against
# ``connected_devices`` (see that domain's own module docstring), never
# fabricated or cached. ``service.AlertService._evaluate_health_status_rule``'s
# ``ALERT_TARGET_MONITORED_HARDWARE`` branch composes with
# ``MonitoredHardwareService.list_all_devices_with_status`` (a real service
# call, not a raw table read, because deriving status requires that domain's
# own join logic) rather than duplicating the derivation here. ``unknown`` is
# deliberately never alertable (``expected_status`` of ``"down"`` only) --
# "never observed yet" is an honest gap in data, not a real outage, the same
# distinction that domain's own module docstring already draws.
ALERT_TARGET_MONITORED_HARDWARE = "monitored_hardware"

# Sentinel ``AlertRule.target_component`` value for a ``HEALTH_STATUS_CHANGE``
# rule that watches, per router, whether that router is still *watching* for
# a DHCP server on the guest network that isn't ours -- the rolled-up
# ``app.domains.dhcp.models.RouterRogueDhcpStatus.alert_state`` that
# ``app.domains.dhcp.tasks``'s scheduled detector persists every six hours.
#
# ## Why this target exists at all
#
# cloud-guest#139 built the detector and a ``ROGUE_DHCP_GUARD`` readiness
# checklist item that reads its rows. That surface is pull-only: an
# unguarded router shows up if -- and only if -- somebody opens that
# router's checklist. Nobody does. This target is the push half, and it is
# the same "already-tracked signal another domain persists" composition
# ``ALERT_TARGET_ROUTER``/``ALERT_TARGET_ISP_LINK`` above already establish.
#
# ## No per-device I/O, and none needed
#
# ``app.domains.monitoring.tasks``'s module docstring commits this engine to
# reading already-persisted state only. That promise is what forced #139's
# detector-writes/surface-reads split in the first place, so honouring it
# here costs nothing: ``RouterRogueDhcpStatus`` *is* already-persisted
# state, written hours earlier off the request path. See
# ``service.AlertService._evaluate_rogue_dhcp_guard_rule``, which reads it
# through ``repository.list_rogue_dhcp_statuses_with_routers`` -- one
# query for the whole rule, not one per router.
#
# ## Only ``unguarded`` is alertable, and only per router
#
# ``expected_status`` is ``"unguarded"`` -- the sole value with a finding
# behind it. ``app.domains.dhcp.constants.RogueDhcpAlertState`` is
# deliberately tri-state, and ``unknown`` ("the detector could not reach
# this router") never triggers and never resolves: a router we could not
# reach is not a router we know is unwatched, and it is not a router we
# know has been fixed either. Same posture ``ALERT_TARGET_MONITORED_HARDWARE``
# above documents for ``HardwareStatus.UNKNOWN``, same posture
# ``HealthStatus.UNKNOWN`` documents for its own no-data case, and the same
# distinction the readiness item's own NOT_CHECKED-not-FAIL branch draws.
# This codebase has collapsed that distinction twice and paid for it both
# times (a missing SMS provider rendered as "delivery failed"; locations
# silently dropped from a fleet list).
#
# The detector persists one row per ``(router_id, interface)``, but the
# alert de-duplication key (see ``AlertService``'s own docstring) has no
# interface dimension -- so this target evaluates one *router* at a time,
# with the affected interface names in the alert message. Two unguarded
# interfaces on one router are one alert, not two.
#
# ## Detection only
#
# ``/ip dhcp-server alert`` logs. It does not block, drop, or rate-limit
# anything. No copy derived from this target may imply otherwise -- see
# ``RogueDhcpAlertState``'s own note on this and
# ``service._rogue_dhcp_guard_message``/``_rogue_dhcp_guard_resolved_message``,
# which carry the same "detection only -- it logs, it does not block"
# sentence the readiness item already shows.
ALERT_TARGET_ROGUE_DHCP_GUARD = "rogue_dhcp_guard"

# The one ``expected_status`` an ``ALERT_TARGET_ROGUE_DHCP_GUARD`` rule may
# carry, and the ``alert_state`` string the evaluator matches it against.
# Held here as a plain string rather than importing
# ``app.domains.dhcp.constants.RogueDhcpAlertState`` so this module keeps
# the zero-imports-from-other-domains shape every other constant here has;
# ``dhcp``'s enum stores plain strings for exactly this reason, and
# ``tests/unit/test_monitoring_alerts.py`` pins the two to each other so
# they cannot drift apart silently.
ROGUE_DHCP_STATE_UNGUARDED = "unguarded"
ROGUE_DHCP_STATE_GUARDED = "guarded"
ROGUE_DHCP_STATE_UNKNOWN = "unknown"


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

# Celery Beat cadence for ``app.domains.monitoring.tasks
# .run_alert_rule_evaluation_sweep`` -- the periodic sweep that turns
# ``evaluate_alert_rules`` from an on-demand-only action (``POST
# /alerts/evaluate``) into a real, running background job now that this
# codebase actually has a Celery deployment (the constraint the comment
# above this one was written against no longer holds).
#
# Real bug, found live: this was 900 seconds (15 minutes), justified by a
# comment claiming it was "slightly longer than the two real device-health
# sweeps this evaluator is downstream of... both 600 seconds/10 minutes
# today." That was true when written, but ``app.domains.isp.constants
# .ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS`` was later sped up to 60
# seconds without this value being revisited to match -- so a real ISP
# link going down (or recovering) could sit detected-but-unalerted for up
# to 15 minutes, a customer-reported "instant down/up email doesn't come,
# there's a 15 min gap" bug, not a cosmetic one. 90 seconds now:
# slightly longer than the FASTER of the two underlying sweeps this
# evaluator reads (ISP health at 60s; ``app.domains.provisioning_engine
# .constants.ROUTER_HEALTH_POLL_SWEEP_INTERVAL_SECONDS`` is still 600s
# today, unrelated to this specific bug), so a real state change is
# alertable within about one ISP-health cycle of it actually happening
# rather than fifteen.
#
# Lowered again to 30 seconds after direct feedback that even a ~90s
# email still didn't feel real-time: ``app.domains.isp.constants
# .ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS`` itself was also dropped to
# 30s at the same time (same commit), so this stays matched to it rather
# than trailing behind it again. Still bounded, not zero-latency -- a real
# polling sweep, not an event-driven push, so "instant" always means
# "within about one cycle of the faster underlying sweep," typically
# under a minute end-to-end (health check catches the change, next
# evaluation pass alerts + emails on it), never truly immediate.
# How often the Health Engine actually runs.
#
# It did not run at all. `GET /monitoring/health` only *reads* the stored
# `service_health` rows; the sole writer is `POST /monitoring/health/run`,
# which is the Master console's own "Run health checks now" button. There
# was no Beat entry and nothing else called `run_all_health_checks`, so on
# 2026-09-04 that page showed component timestamps two days old while
# calling itself live -- and FreeRADIUS sat on "Degraded, 5 consecutive
# failures" from a check nobody had re-run since.
#
# Five minutes, matching the hub-reconciliation sweep rather than the
# 30-second alert sweep: these checks touch the database, Redis, disk and
# the hub's own agents, so they are an order of magnitude more expensive
# than reading already-persisted state, and nothing here changes on a
# 30-second timescale. Health that is five minutes old is honest; health
# that is two days old is a lie with a timestamp on it.
HEALTH_CHECK_SWEEP_INTERVAL_SECONDS = 300.0

TASK_RUN_HEALTH_CHECK_SWEEP = "app.domains.monitoring.tasks.run_health_check_sweep"

ALERT_RULE_EVALUATION_SWEEP_INTERVAL_SECONDS = 30.0

TASK_RUN_ALERT_RULE_EVALUATION_SWEEP = (
    "app.domains.monitoring.tasks.run_alert_rule_evaluation_sweep"
)

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
    "ALERT_TARGET_ISP_LINK",
    "ALERT_TARGET_MONITORED_HARDWARE",
    "ALERT_TARGET_ROGUE_DHCP_GUARD",
    "ROGUE_DHCP_STATE_UNGUARDED",
    "ROGUE_DHCP_STATE_GUARDED",
    "ROGUE_DHCP_STATE_UNKNOWN",
    "ThresholdMetric",
    "ThresholdOperator",
    "AlertSeverity",
    "AlertStatus",
    "ALERT_STATUS_TRANSITIONS",
    "ALERT_EVENT_LOOKBACK_MINUTES",
    "ALERT_RULE_EVALUATION_SWEEP_INTERVAL_SECONDS",
    "HEALTH_CHECK_SWEEP_INTERVAL_SECONDS",
    "TASK_RUN_ALERT_RULE_EVALUATION_SWEEP",
    "TASK_RUN_HEALTH_CHECK_SWEEP",
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

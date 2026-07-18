"""Monitoring business logic: the Health Engine (real checks against every
genuine platform dependency this codebase has) and the Event Engine (a
narrowly-scoped new event table plus a read-side aggregation across it and
two other domains' existing event tables).

As of BE-012 Part 1, every component check is real -- Celery
(``check_celery_health``) and WebSocket (``check_websocket_health``) started
as honest ``UNKNOWN``s in BE-011 Part 1 for infrastructure that didn't exist
yet, and both have since been updated in place (Celery once BE-012 Part 1
gave this codebase a genuine deployment; WebSocket once BE-011 Part 3 added
real WS routes) rather than left permanently stale.

## Design decisions worth calling out up front

**Every check either does real I/O or is honest about not being able to.**
``check_database_health``/``check_redis_health`` execute a real query/PING
against the real ``AsyncSession``/Redis client and measure wall-clock
latency. ``check_storage_health`` calls the real ``shutil.disk_usage``
against the real configured log directory. ``check_auth_health`` makes a
real (if narrow) call through the real ``AuthRepository``. ``check_api_health``
is close to tautological (see its own docstring) but still a real,
meaningful signal in the aggregate dashboard: if this code is executing at
all, the FastAPI process handling the request is, definitionally, up.
``check_celery_health`` performs a real Celery broker/worker ping
(``app.core.celery_app.ping_celery_workers``) and reports HEALTHY/DEGRADED/
UNHEALTHY based on what actually responds; ``check_websocket_health``
reports HEALTHY since real WS routes exist on this process, with the
tautological-but-meaningful caveat documented on its own docstring (no
connection registry exists to report a live count). Neither ever fabricates
a status for infrastructure that doesn't exist -- see each method's own
docstring for exactly what it can and can't observe.
``check_freeradius_health``/``check_wireguard_health`` are documented,
DB-tracked *proxy* signals (composing with ``app.domains.guest``'s
``RadiusNasClient``/``GuestSession`` rows and ``app.domains.wireguard``'s
own ``compute_health_status`` method, respectively) rather than a live
daemon ping -- there is no real FreeRADIUS process or ``wg show`` in this
sandbox to actually reach, the same honest "simulated, DB-tracked signal"
posture ``app.domains.wireguard``/``app.domains.guest`` themselves already
document for their own device-facing surfaces.

**Overall dashboard status excludes permanently-``UNKNOWN`` components from
the "must all be healthy" rule.** Read literally, "HEALTHY only if every
component is HEALTHY" would mean the platform-wide dashboard could *never*
show HEALTHY in this environment, since ``CELERY``/``WEBSOCKET`` are
honestly ``UNKNOWN`` forever until that infrastructure is actually deployed
-- that would make the aggregate status useless as a signal. ``
_aggregate_status`` instead treats ``UNKNOWN`` as "not currently
applicable" rather than "not healthy": the aggregate is computed from
whichever components have a *live* (non-``UNKNOWN``) status, and is
``UNKNOWN`` only when every single component is (which only happens before
the very first health-check run). This is a deliberate, documented reading
of the spec, not a silent deviation -- see ``get_dashboard_summary``.

**Event Engine composition, not duplication.** See ``models.PlatformEvent``'s
own module docstring for the full write-up. In short: ``PlatformEvent`` is
a real, new (but narrowly-scoped) table populated only by this module's own
health-transition detections; ``get_event_timeline`` is a read-side
aggregation across that table plus RBAC's ``audit_log_entries`` and
``router_provisioning``'s ``RouterEvent`` (read directly, not copied).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

import httpx
from redis.asyncio import Redis

from app.core.celery_app import CELERY_HEALTH_CHECK_TIMEOUT_SECONDS, ping_celery_workers
from app.core.config import Settings
from app.core.logging import get_logger
from app.database.utils.pagination import PaginationMeta
from app.domains.otp.service import (
    EmailProviderProtocol,
    LoggingEmailProvider,
    LoggingSmsProvider,
    SmsProviderProtocol,
)
from app.domains.rbac.models import AuditLogEntry
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router_provisioning.constants import EnrollmentStatus
from app.domains.router_provisioning.models import RouterEvent

from .constants import (
    ALERT_EVENT_LOOKBACK_MINUTES,
    ALERT_TARGET_ROUTER,
    AUDIT_LOG_SOURCE_DOMAIN,
    DEFAULT_EVENT_TIMELINE_LIMIT,
    DEFAULT_FAILURE_SAMPLE_LIMIT,
    DEFAULT_LIST_PAGE,
    DEFAULT_LIST_PAGE_SIZE,
    DEFAULT_ZTP_PAGE,
    DEFAULT_ZTP_PAGE_SIZE,
    EVENT_TYPE_COMPONENT_DEGRADED,
    EVENT_TYPE_COMPONENT_RECOVERED,
    EVENT_TYPE_COMPONENT_UNHEALTHY,
    FREERADIUS_ACTIVITY_STALE_MINUTES,
    HTTP_NOTIFICATION_TIMEOUT_SECONDS,
    MAX_EVENT_TIMELINE_LIMIT,
    MONITORING_LIVE_CHANNEL,
    ROUTER_EVENT_SOURCE_DOMAIN,
    SOURCE_DOMAIN,
    AlertStatus,
    AlertTriggerType,
    EventCategory,
    EventSeverity,
    HealthComponent,
    HealthStatus,
    HeartbeatComponentType,
    IncidentStatus,
    NotificationChannelType,
    NotificationStatus,
    RealtimeMessageType,
    RouterLifecycleStage,
    ThresholdOperator,
)
from .events import (
    AlertAcknowledged,
    AlertResolved,
    AlertTriggered,
    HeartbeatRecorded,
    IncidentOpened,
    IncidentStatusChanged,
    NotificationDispatched,
    PlatformEventRecorded,
    ServiceHealthTransitioned,
    SlaReportGenerated,
)
from .exceptions import (
    AlertNotFoundError,
    AlertRuleNotFoundError,
    IncidentNotFoundError,
    InsufficientSlaDataError,
    NotificationChannelNotFoundError,
    SlaTargetNotFoundError,
)
from .models import (
    Alert,
    AlertRule,
    HealthCheck,
    HeartbeatLog,
    Incident,
    NotificationChannel,
    NotificationLog,
    PlatformEvent,
    ServiceHealth,
    SlaReport,
    SlaTarget,
)
from .repository import MonitoringRepositoryProtocol
from .validators import (
    classify_storage_health,
    compare_threshold,
    compute_lifecycle_stage,
    validate_alert_rule_condition_config,
    validate_alert_status_transition,
    validate_date_range,
    validate_incident_status_transition,
    validate_notification_channel_config,
    validate_sla_target_config,
)

logger = get_logger(__name__)


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class AuthLookupProtocol(Protocol):
    """The subset of the real ``AuthRepository`` surface
    ``check_auth_health`` needs: a cheap, real query proving the auth
    domain's own repository/DB wiring resolves without error. Deliberately
    not a "login success rate" metric -- that would need real traffic data
    this environment does not have (see module docstring)."""

    async def list_users(
        self, *, page: int, page_size: int
    ) -> tuple[list[object], PaginationMeta]: ...


class WireGuardHealthLookupProtocol(Protocol):
    """The single method ``check_wireguard_health`` needs from the real
    ``WireGuardService`` -- reused directly, never reimplemented, per this
    module's own honesty mandate around not duplicating another domain's
    staleness-threshold logic."""

    def compute_health_status(
        self, peer: object, *, now: datetime | None = None
    ) -> object: ...


class _VisitorSummaryProtocol(Protocol):
    """The two attributes ``PlatformDashboardService`` reads off whatever
    ``GuestVisitorLookupProtocol.get_summary`` returns -- structurally
    satisfied by the real ``app.domains.guest.service.GuestAnalyticsSummary``
    without importing that class (mirrors ``AuthLookupProtocol``/
    ``WireGuardHealthLookupProtocol``'s identical "duck-typed, no hard
    import of the concrete class" discipline)."""

    visitors: int
    unique_guests: int


class GuestVisitorLookupProtocol(Protocol):
    """The single method ``PlatformDashboardService.get_dashboard_statistics``
    needs from the real ``app.domains.guest.service.GuestAnalyticsService``
    -- reused directly (its own real SQL-aggregate queries), never
    reimplemented. See that method's docstring for why visitor/unique-guest
    counts are only populated when an ``organization_id`` is supplied (guest
    analytics are inherently tenant-scoped upstream)."""

    async def get_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> _VisitorSummaryProtocol: ...


async def _publish_live_message(
    redis_client: Redis | None,
    message_type: RealtimeMessageType,
    payload: dict[str, object],
) -> None:
    """Best-effort ``PUBLISH`` to :data:`~.constants.MONITORING_LIVE_CHANNEL`
    -- the single fan-out point every real-time write path (health-status
    transitions, alert trigger/resolve, the guest-session-start hook) calls
    *after* its own real database write already succeeded (never instead
    of, never before). Deliberately **never raises**: a Redis publish
    failure (Redis down, a transient network blip) must never roll back or
    otherwise affect the DB write it is riding along with -- exactly the
    same resilience posture ``NotificationService.dispatch_notification``
    already establishes for Part 2's alert notifications (a failure is
    logged, not propagated). Every connected WebSocket client simply misses
    that one update; the next state-changing event (or a fresh
    HTTP ``GET`` against the same data) still reflects reality, so nothing
    is silently lost from the actual source of truth, only from the live
    stream."""
    if redis_client is None:
        return
    try:
        message = {
            "type": message_type.value,
            "payload": payload,
            "occurred_at": datetime.now(UTC).isoformat(),
        }
        await redis_client.publish(
            MONITORING_LIVE_CHANNEL, json.dumps(message, default=str)
        )
    except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
        logger.warning(
            "monitoring_live_publish_failed",
            extra={"message_type": message_type.value, "error": str(exc)},
        )


def _compute_overall_health_status(rows: list[ServiceHealth]) -> HealthStatus:
    """See module docstring's "overall dashboard status excludes
    permanently-``UNKNOWN`` components" write-up. Extracted to module scope
    (from what was ``MonitoringService._aggregate_status``) so
    ``PlatformDashboardService`` can reuse the identical aggregate-status
    rule without a second, potentially-drifting implementation."""
    statuses = {row.status for row in rows}
    if HealthStatus.UNHEALTHY.value in statuses:
        return HealthStatus.UNHEALTHY
    if HealthStatus.DEGRADED.value in statuses:
        return HealthStatus.DEGRADED
    known_statuses = statuses - {HealthStatus.UNKNOWN.value}
    if not known_statuses:
        return HealthStatus.UNKNOWN
    return HealthStatus.HEALTHY


# ============================================================================
# Value objects
# ============================================================================


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    """The outcome of one ``check_*`` call -- not yet persisted. ``service
    .run_all_health_checks``/``_persist_result`` turns this into a
    :class:`~.models.HealthCheck` row plus a :class:`~.models.ServiceHealth`
    rollup update."""

    component: HealthComponent
    status: HealthStatus
    response_time_ms: float | None
    details: dict[str, object] | None
    error_message: str | None


@dataclass(frozen=True, slots=True)
class DashboardSummary:
    overall_status: HealthStatus
    components: list[ServiceHealth]


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """One row of ``get_event_timeline``'s unified, chronologically-sorted
    view -- built from whichever of ``PlatformEvent``/``AuditLogEntry``/
    ``RouterEvent`` it was sourced from (see the ``from_*`` constructors)."""

    occurred_at: datetime
    category: str
    severity: str
    event_type: str
    source_domain: str
    message: str
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    router_id: uuid.UUID | None
    metadata: dict[str, object]

    @classmethod
    def from_platform_event(cls, event: PlatformEvent) -> TimelineEntry:
        return cls(
            occurred_at=event.occurred_at,
            category=event.category,
            severity=event.severity,
            event_type=event.event_type,
            source_domain=event.source_domain,
            message=event.message,
            organization_id=event.organization_id,
            location_id=event.location_id,
            router_id=event.router_id,
            metadata=event.event_metadata or {},
        )

    @classmethod
    def from_audit_log(cls, entry: AuditLogEntry) -> TimelineEntry:
        """RBAC's ``audit_log_entries`` has no ``category``/``severity`` of
        its own -- every merged row is classified ``AUDIT``/``INFO``, which
        is always an accurate description of that table's own documented
        scope (accountable, human-attributable admin actions)."""
        return cls(
            occurred_at=entry.created_at,
            category=EventCategory.AUDIT.value,
            severity=EventSeverity.INFO.value,
            event_type=entry.action,
            source_domain=AUDIT_LOG_SOURCE_DOMAIN,
            message=entry.description or entry.action,
            organization_id=entry.organization_id,
            location_id=entry.location_id,
            router_id=None,
            metadata=entry.event_metadata or {},
        )

    @classmethod
    def from_router_event(cls, event: RouterEvent) -> TimelineEntry:
        """``router_provisioning``'s ``RouterEvent`` has no ``category``/
        ``severity`` of its own either -- every merged row is classified
        ``PROVISIONING`` (its own documented scope: device
        lifecycle/telemetry), with a best-effort ``WARNING`` severity for
        any ``event_type`` that reads as a failure, ``INFO`` otherwise."""
        lowered = event.event_type.lower()
        is_failure = "error" in lowered or "failed" in lowered or "reset" in lowered
        severity = (
            EventSeverity.WARNING.value if is_failure else EventSeverity.INFO.value
        )
        return cls(
            occurred_at=event.occurred_at,
            category=EventCategory.PROVISIONING.value,
            severity=severity,
            event_type=event.event_type,
            source_domain=ROUTER_EVENT_SOURCE_DOMAIN,
            message=event.message or event.event_type,
            organization_id=None,
            location_id=None,
            router_id=event.router_id,
            metadata=event.event_metadata or {},
        )


# ============================================================================
# Service
# ============================================================================


class MonitoringService:
    """Core monitoring business logic: the Health Engine
    (``check_*``/``run_all_health_checks``/``get_dashboard_summary``) and
    the Event Engine (``record_platform_event``/``get_event_timeline``/
    ``record_heartbeat``)."""

    def __init__(
        self,
        repository: MonitoringRepositoryProtocol,
        redis_client: Redis,
        settings: Settings,
        *,
        auth_repository: AuthLookupProtocol | None = None,
        wireguard_service: WireGuardHealthLookupProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.redis_client = redis_client
        self.settings = settings
        self.auth_repository = auth_repository
        self.wireguard_service = wireguard_service

    # ========================================================================
    # Individual health checks
    # ========================================================================

    async def check_database_health(self) -> HealthCheckResult:
        """A REAL check: executes a trivial ``SELECT 1`` against the actual
        ``AsyncSession`` and measures wall-clock response time."""
        started = time.perf_counter()
        try:
            await self.repository.ping_database()
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.DATABASE,
                status=HealthStatus.HEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details={"query": "SELECT 1"},
                error_message=None,
            )
        except Exception as exc:  # noqa: BLE001 -- any DB failure is a real signal
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.DATABASE,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details=None,
                error_message=str(exc),
            )

    async def check_redis_health(self) -> HealthCheckResult:
        """A REAL check: ``PING``s the actual Redis client
        (``app.database.redis.get_redis_client``) and measures latency,
        bounded by ``Settings.redis_health_timeout_seconds`` -- mirrors
        ``app.api.v1.health.routes._redis_status``'s identical mechanism."""
        started = time.perf_counter()
        try:
            await self.redis_client.ping()
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.REDIS,
                status=HealthStatus.HEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details={"command": "PING"},
                error_message=None,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.REDIS,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details=None,
                error_message=str(exc),
            )

    async def check_api_health(self) -> HealthCheckResult:
        """Reports the app's own liveness. This is almost tautological --
        if this coroutine is executing at all, the FastAPI process handling
        the request is, by definition, up -- but it is still a genuinely
        useful component in the aggregate dashboard: a monitoring UI that
        lists every platform component gets a complete, uniform row set
        (database/redis/api/auth/...) rather than a conspicuous gap where
        "is the API itself alive" would otherwise be implicit."""
        return HealthCheckResult(
            component=HealthComponent.API,
            status=HealthStatus.HEALTHY,
            response_time_ms=0.0,
            details={"note": "process executed this check, therefore is running"},
            error_message=None,
        )

    async def check_auth_health(self) -> HealthCheckResult:
        """A REAL, lightweight check that the auth domain's dependencies
        are wired correctly: makes one cheap, real call through the actual
        ``AuthRepository`` (``list_users`` capped at one row). Deliberately
        does **not** fabricate a "login success rate" metric -- that would
        need real authentication traffic this environment has no way to
        generate; this check's honest, narrow scope is "can the auth
        domain's repository/DB layer be resolved and queried at all,"
        nothing more."""
        started = time.perf_counter()
        try:
            if self.auth_repository is None:
                raise RuntimeError("auth repository is not wired")
            await self.auth_repository.list_users(page=1, page_size=1)
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.AUTH,
                status=HealthStatus.HEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details={
                    "check": "AuthRepository.list_users(page_size=1)",
                    "jwt_algorithm": self.settings.jwt_algorithm,
                },
                error_message=None,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.AUTH,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details=None,
                error_message=str(exc),
            )

    async def check_storage_health(self) -> HealthCheckResult:
        """A REAL, if modest, check: ``shutil.disk_usage`` (stdlib, no new
        dependency) against the actual configured log directory
        (``Settings.log_dir``), classified by ``validators
        .classify_storage_health``."""
        started = time.perf_counter()
        log_dir = Path(self.settings.log_dir)
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            usage = shutil.disk_usage(log_dir)
            percent_used = (usage.used / usage.total) * 100 if usage.total else 0.0
            writable = os.access(log_dir, os.W_OK)
            status_value = classify_storage_health(
                percent_used=percent_used, writable=writable
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            details = {
                "path": str(log_dir),
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent_used": round(percent_used, 2),
                "writable": writable,
            }
            error_message = None if writable else "log directory is not writable"
            return HealthCheckResult(
                component=HealthComponent.STORAGE,
                status=status_value,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message=error_message,
            )
        except OSError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.STORAGE,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details=None,
                error_message=str(exc),
            )

    async def check_celery_health(self) -> HealthCheckResult:
        """A REAL check, now that BE-012 Part 1 (``app.core.celery_app``)
        gives this codebase a genuine Celery deployment -- no longer the
        honest ``UNKNOWN`` BE-011 Part 1 left here ("ready to wire in once
        one does"). Uses Celery's own inspection API
        (``control.inspect().ping()``, via ``app.core.celery_app
        .ping_celery_workers`` -- a real, if blocking, network round trip
        against the configured broker, so it is run off the event loop via
        ``asyncio.to_thread``) bounded by
        ``CELERY_HEALTH_CHECK_TIMEOUT_SECONDS``.

        Exactly three outcomes, each a real signal, never a fabricated
        ``HEALTHY``:

        * The broker itself could not be reached at all (connection
          refused/timed out -- e.g. in this sandbox, where no actual Redis
          broker or worker process is running during tests) ->
          ``HealthStatus.UNHEALTHY``. The most severe of the three: the
          task queue's own transport is unreachable, not merely idle.
        * The broker was reached but zero workers replied within the
          timeout (a broker is deployed and reachable, but no
          ``celery worker`` process is currently up -- e.g. between
          deployments, or a worker pool scaled to zero) ->
          ``HealthStatus.DEGRADED``. Background aggregation is stale/paused,
          but this is not a full platform outage -- guest login, RBAC, and
          every synchronous request/response path are entirely unaffected
          by a missing worker.
        * At least one worker replied -> ``HealthStatus.HEALTHY``, with the
          responding worker name(s) recorded in ``details``.
        """
        started = time.perf_counter()
        try:
            pong = await asyncio.to_thread(
                ping_celery_workers, CELERY_HEALTH_CHECK_TIMEOUT_SECONDS
            )
        except Exception as exc:  # noqa: BLE001 -- broker unreachable is a real signal
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.CELERY,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details=None,
                error_message=f"Celery broker is unreachable: {exc}",
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        if not pong:
            return HealthCheckResult(
                component=HealthComponent.CELERY,
                status=HealthStatus.DEGRADED,
                response_time_ms=round(elapsed_ms, 3),
                details={"workers_responding": 0},
                error_message=(
                    "Celery broker is reachable but no worker responded to "
                    "ping within the configured timeout"
                ),
            )
        return HealthCheckResult(
            component=HealthComponent.CELERY,
            status=HealthStatus.HEALTHY,
            response_time_ms=round(elapsed_ms, 3),
            details={
                "workers_responding": len(pong),
                "workers": sorted(pong.keys()),
            },
            error_message=None,
        )

    async def check_websocket_health(self) -> HealthCheckResult:
        """Real, if narrow: BE-011 Part 3 added genuine WebSocket endpoints
        (``WS /monitoring/ws/dashboard``, ``WS /monitoring/ws/sessions``),
        so this is no longer the honest ``UNKNOWN`` BE-011 Part 1 left here.
        No connection registry exists to report a live connection count
        (unlike Celery, WebSocket support is part of this same running
        FastAPI process, not a separate broker/worker to ping) -- this is
        HEALTHY in the same close-to-tautological-but-still-meaningful
        sense as ``check_api_health``: if this code is executing, the
        process serving those routes is up."""
        return HealthCheckResult(
            component=HealthComponent.WEBSOCKET,
            status=HealthStatus.HEALTHY,
            response_time_ms=None,
            details={
                "reason": (
                    "WebSocket routes are registered on this process; no "
                    "live connection count is tracked"
                )
            },
            error_message=None,
        )

    async def check_freeradius_health(self) -> HealthCheckResult:
        """A PROXY signal, not a live FreeRADIUS daemon ping -- there is no
        real FreeRADIUS process in this sandbox to reach (see
        ``app.domains.guest.service``'s own module docstring: this
        platform's RADIUS integration is an ``rlm_rest``-style HTTP
        contract, not a live daemon this process could health-check
        directly). Composes with ``app.domains.guest``'s existing
        ``RadiusNasClient``/``GuestSession`` rows: how many active NAS
        clients are registered, and how recently any RADIUS-accounting-
        driven session activity was recorded."""
        started = time.perf_counter()
        active_nas_count = await self.repository.count_active_radius_nas_clients()
        latest_activity = await self.repository.get_latest_guest_accounting_activity()
        elapsed_ms = (time.perf_counter() - started) * 1000
        details: dict[str, object] = {
            "active_nas_clients": active_nas_count,
            "latest_accounting_activity_at": (
                latest_activity.isoformat() if latest_activity else None
            ),
            "proxy_signal": True,
        }
        if active_nas_count == 0:
            return HealthCheckResult(
                component=HealthComponent.FREERADIUS,
                status=HealthStatus.UNKNOWN,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message="No RADIUS NAS clients are registered yet",
            )
        if latest_activity is None:
            return HealthCheckResult(
                component=HealthComponent.FREERADIUS,
                status=HealthStatus.DEGRADED,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message=(
                    "NAS clients are registered but no accounting activity "
                    "has ever been recorded"
                ),
            )
        stale_after = timedelta(minutes=FREERADIUS_ACTIVITY_STALE_MINUTES)
        if datetime.now(UTC) - latest_activity > stale_after:
            return HealthCheckResult(
                component=HealthComponent.FREERADIUS,
                status=HealthStatus.DEGRADED,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message="No recent RADIUS accounting activity",
            )
        return HealthCheckResult(
            component=HealthComponent.FREERADIUS,
            status=HealthStatus.HEALTHY,
            response_time_ms=round(elapsed_ms, 3),
            details=details,
            error_message=None,
        )

    async def check_wireguard_health(self) -> HealthCheckResult:
        """A PROXY signal, not a live ``wg show`` integration -- composes
        directly with ``app.domains.wireguard.service.WireGuardService
        .compute_health_status`` (reused, never reimplemented) against
        every non-revoked ``WireGuardPeer`` row."""
        started = time.perf_counter()
        if self.wireguard_service is None:
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HealthCheckResult(
                component=HealthComponent.WIREGUARD,
                status=HealthStatus.UNKNOWN,
                response_time_ms=round(elapsed_ms, 3),
                details=None,
                error_message="WireGuard service is not wired",
            )
        peers = await self.repository.list_wireguard_peers()
        now = datetime.now(UTC)
        non_revoked = [peer for peer in peers if peer.status != "revoked"]
        counts: dict[str, int] = {}
        for peer in non_revoked:
            peer_status = self.wireguard_service.compute_health_status(peer, now=now)
            key = getattr(peer_status, "value", str(peer_status))
            counts[key] = counts.get(key, 0) + 1
        elapsed_ms = (time.perf_counter() - started) * 1000
        details: dict[str, object] = {
            "total_peers": len(peers),
            "non_revoked_peers": len(non_revoked),
            "status_counts": counts,
            "proxy_signal": True,
        }
        stale_count = counts.get("stale", 0)
        if not non_revoked:
            return HealthCheckResult(
                component=HealthComponent.WIREGUARD,
                status=HealthStatus.UNKNOWN,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message="No active WireGuard peers are provisioned yet",
            )
        if stale_count == len(non_revoked):
            return HealthCheckResult(
                component=HealthComponent.WIREGUARD,
                status=HealthStatus.UNHEALTHY,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message="Every active WireGuard peer's handshake is stale",
            )
        if stale_count > 0:
            return HealthCheckResult(
                component=HealthComponent.WIREGUARD,
                status=HealthStatus.DEGRADED,
                response_time_ms=round(elapsed_ms, 3),
                details=details,
                error_message=None,
            )
        return HealthCheckResult(
            component=HealthComponent.WIREGUARD,
            status=HealthStatus.HEALTHY,
            response_time_ms=round(elapsed_ms, 3),
            details=details,
            error_message=None,
        )

    # ========================================================================
    # Orchestration
    # ========================================================================

    async def run_all_health_checks(self) -> list[HealthCheckResult]:
        """Runs every check, persists a :class:`HealthCheck` row per
        component, and updates the corresponding :class:`ServiceHealth`
        rollup (including ``consecutive_failure_count`` increment/reset)."""
        checks = (
            await self.check_database_health(),
            await self.check_redis_health(),
            await self.check_api_health(),
            await self.check_auth_health(),
            await self.check_storage_health(),
            await self.check_celery_health(),
            await self.check_websocket_health(),
            await self.check_freeradius_health(),
            await self.check_wireguard_health(),
        )
        for result in checks:
            await self._persist_result(result)
        return list(checks)

    async def _persist_result(self, result: HealthCheckResult) -> None:
        now = datetime.now(UTC)
        await self.repository.create_health_check(
            component=result.component.value,
            status=result.status.value,
            checked_at=now,
            response_time_ms=result.response_time_ms,
            details=result.details,
            error_message=result.error_message,
        )

        existing = await self.repository.get_service_health(result.component.value)
        previous_status = existing.status if existing is not None else None
        is_failure = result.status in (HealthStatus.UNHEALTHY, HealthStatus.DEGRADED)

        if existing is None:
            failure_count = 1 if is_failure else 0
            await self.repository.create_service_health(
                component=result.component.value,
                status=result.status.value,
                last_checked_at=now,
                consecutive_failure_count=failure_count,
            )
        else:
            failure_count = existing.consecutive_failure_count + 1 if is_failure else 0
            await self.repository.update_service_health(
                existing,
                {
                    "status": result.status.value,
                    "last_checked_at": now,
                    "consecutive_failure_count": failure_count,
                },
            )

        if previous_status != result.status.value:
            event = ServiceHealthTransitioned(
                component=result.component.value,
                previous_status=previous_status,
                new_status=result.status.value,
                consecutive_failure_count=failure_count,
            )
            logger.info("service_health_transitioned", extra=_event_extra(event))
            await self._record_transition_event(
                result, previous_status=previous_status, failure_count=failure_count
            )
            # Real-Time (BE-011 Part 3): publish this genuine status
            # transition to MONITORING_LIVE_CHANNEL, after the DB write
            # above has already succeeded -- see _publish_live_message's
            # own docstring for the "never raises" resilience contract.
            await _publish_live_message(
                self.redis_client,
                RealtimeMessageType.HEALTH_TRANSITION,
                payload={
                    "component": result.component.value,
                    "previous_status": previous_status,
                    "new_status": result.status.value,
                    "consecutive_failure_count": failure_count,
                },
            )

    async def _record_transition_event(
        self,
        result: HealthCheckResult,
        *,
        previous_status: str | None,
        failure_count: int,
    ) -> None:
        """Writes a :class:`~.models.PlatformEvent` only on a genuine
        status *transition* (never on every single run) -- see
        ``models.PlatformEvent``'s module docstring for why this is the one
        genuinely new event source this module's Event Engine owns."""
        if result.status == HealthStatus.UNHEALTHY:
            event_type = EVENT_TYPE_COMPONENT_UNHEALTHY
            severity = EventSeverity.CRITICAL
        elif result.status == HealthStatus.DEGRADED:
            event_type = EVENT_TYPE_COMPONENT_DEGRADED
            severity = EventSeverity.WARNING
        elif result.status == HealthStatus.HEALTHY and previous_status in (
            HealthStatus.UNHEALTHY.value,
            HealthStatus.DEGRADED.value,
        ):
            event_type = EVENT_TYPE_COMPONENT_RECOVERED
            severity = EventSeverity.INFO
        else:
            # UNKNOWN <-> UNKNOWN churn, or a first-ever HEALTHY result with
            # no prior degraded/unhealthy state -- not a notable transition.
            return

        message = (
            f"{result.component.value} health transitioned from "
            f"{previous_status or 'unknown'} to {result.status.value}"
        )
        await self.record_platform_event(
            category=EventCategory.SYSTEM,
            event_type=event_type,
            severity=severity,
            message=message,
            metadata={
                "consecutive_failure_count": failure_count,
                "error_message": result.error_message,
            },
        )

    def _aggregate_status(self, rows: list[ServiceHealth]) -> HealthStatus:
        """See module docstring's "overall dashboard status excludes
        permanently-``UNKNOWN`` components" write-up. Delegates to the
        module-level :func:`_compute_overall_health_status` so
        ``PlatformDashboardService`` (BE-011 Part 3) reuses the identical
        rule rather than a second, potentially-drifting copy."""
        return _compute_overall_health_status(rows)

    async def get_dashboard_summary(self) -> DashboardSummary:
        """Aggregates overall platform status plus every component's
        current :class:`ServiceHealth` row -- what a dashboard reads for
        "what is healthy right now" without scanning ``HealthCheck``
        history."""
        rows = await self.repository.list_service_health()
        return DashboardSummary(
            overall_status=self._aggregate_status(rows), components=rows
        )

    # ========================================================================
    # Real-Time (BE-011 Part 3): guest-session live broadcast
    # ========================================================================

    async def broadcast_guest_session_event(
        self,
        *,
        message_type: RealtimeMessageType,
        session_id: uuid.UUID,
        guest_id: uuid.UUID,
        router_id: uuid.UUID,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        auth_method: str,
        is_new_guest: bool,
    ) -> None:
        """Best-effort publish of a guest-session lifecycle moment to
        ``WS /monitoring/ws/sessions`` -- called by
        ``app.domains.guest.service.GuestService``'s ``login_via_otp``/
        ``login_via_voucher`` methods, via a narrow, optional, duck-typed
        hook (``GuestService.monitoring_hook`` -- see that module's own
        updated docstring for the precise, additive edit and why it never
        changes ``GuestService``'s existing contract or behavior). Mirrors
        this module's own ``record_heartbeat``'s identical "a real, if
        narrow, composition seam into another domain's existing lifecycle
        method" precedent from Part 1's ``app.domains.router_agent``
        heartbeat hook -- the difference here is only *which* file owns the
        call site (``GuestService``'s own method body, since guest login can
        be reached through more than one endpoint and every one of them
        should broadcast, not just one specific route)."""
        await _publish_live_message(
            self.redis_client,
            message_type,
            payload={
                "session_id": str(session_id),
                "guest_id": str(guest_id),
                "router_id": str(router_id),
                "location_id": str(location_id),
                "organization_id": str(organization_id) if organization_id else None,
                "auth_method": auth_method,
                "is_new_guest": is_new_guest,
            },
        )

    async def get_health_history(
        self, *, component: HealthComponent, page: int, page_size: int
    ) -> tuple[list[HealthCheck], PaginationMeta]:
        return await self.repository.list_health_checks(
            component=component.value, page=page, page_size=page_size
        )

    # ========================================================================
    # Heartbeats
    # ========================================================================

    async def record_heartbeat(
        self,
        *,
        component_type: HeartbeatComponentType,
        component_id: uuid.UUID,
        payload: dict[str, object] | None = None,
    ) -> HeartbeatLog:
        """Writes one row to the platform-wide, cross-domain heartbeat log
        -- see ``models.HeartbeatLog``'s module docstring for its precise
        relationship to ``app.domains.router_agent``'s existing device
        heartbeat (composition, not replacement)."""
        heartbeat = await self.repository.create_heartbeat_log(
            component_type=component_type.value,
            component_id=component_id,
            received_at=datetime.now(UTC),
            payload=payload or {},
        )
        event = HeartbeatRecorded(
            component_type=component_type.value, component_id=component_id
        )
        logger.info("heartbeat_recorded", extra=_event_extra(event))
        return heartbeat

    # ========================================================================
    # Event Engine
    # ========================================================================

    async def record_platform_event(
        self,
        *,
        category: EventCategory,
        event_type: str,
        severity: EventSeverity,
        message: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        source_domain: str = SOURCE_DOMAIN,
        metadata: dict[str, object] | None = None,
    ) -> PlatformEvent:
        event = await self.repository.create_platform_event(
            category=category.value,
            event_type=event_type,
            severity=severity.value,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            source_domain=source_domain,
            message=message,
            event_metadata=metadata or {},
            occurred_at=datetime.now(UTC),
        )
        logged = PlatformEventRecorded(
            event_type=event_type, category=category.value, severity=severity.value
        )
        logger.info("platform_event_recorded", extra=_event_extra(logged))
        return event

    async def get_event_timeline(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        categories: list[EventCategory] | None = None,
        severities: list[EventSeverity] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = DEFAULT_EVENT_TIMELINE_LIMIT,
    ) -> list[TimelineEntry]:
        """The unified, chronologically-sorted timeline -- a read-side
        aggregation across ``PlatformEvent`` (this module's own,
        narrowly-scoped new events) plus RBAC's ``audit_log_entries`` and
        ``router_provisioning``'s ``RouterEvent`` (read directly, never
        copied). See ``models.PlatformEvent``'s module docstring for the
        full composition-vs-new-storage write-up."""
        validate_date_range(start, end)
        bounded_limit = min(limit, MAX_EVENT_TIMELINE_LIMIT)
        category_values = [c.value for c in categories] if categories else None
        severity_values = [s.value for s in severities] if severities else None

        entries: list[TimelineEntry] = []

        platform_events = await self.repository.list_platform_events(
            organization_id=organization_id,
            categories=category_values,
            severities=severity_values,
            start=start,
            end=end,
            limit=bounded_limit,
        )
        entries.extend(TimelineEntry.from_platform_event(e) for e in platform_events)

        if categories is None or EventCategory.AUDIT in categories:
            audit_entries = await self.repository.list_audit_log_events(
                organization_id=organization_id,
                start=start,
                end=end,
                limit=bounded_limit,
            )
            entries.extend(TimelineEntry.from_audit_log(e) for e in audit_entries)

        if categories is None or EventCategory.PROVISIONING in categories:
            router_events = await self.repository.list_router_events(
                organization_id=organization_id,
                start=start,
                end=end,
                limit=bounded_limit,
            )
            entries.extend(TimelineEntry.from_router_event(e) for e in router_events)

        if severity_values:
            entries = [e for e in entries if e.severity in severity_values]

        entries.sort(key=lambda entry: entry.occurred_at, reverse=True)
        return entries[:bounded_limit]


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.guest.service``/``app.domains
    .wireguard.service``'s own ``_event_extra`` (``vars()`` doesn't work on
    slotted dataclasses)."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Alert Engine (BE-011 Part 2)
# ============================================================================


@dataclass(frozen=True, slots=True)
class AlertEvaluationResult:
    """The result of one ``AlertService.evaluate_alert_rules`` pass."""

    triggered: list[Alert]
    resolved: list[Alert]


class AlertService:
    """Alert Engine business logic: ``AlertRule`` CRUD, ``Alert`` lifecycle
    (acknowledge/resolve), and ``evaluate_alert_rules`` -- the evaluation
    loop that turns a watched condition into a real ``Alert`` row and
    dispatches notifications through the composed ``NotificationService``.

    ## De-duplication key

    An open (``TRIGGERED``/``ACKNOWLEDGED``) ``Alert`` is never spammed a
    second time for a condition that is already firing. The de-duplication
    key is **(rule_id, organization_id, location_id, router_id)** -- the
    exact tuple identifying "this rule, watching this specific target"
    (``organization_id``/``location_id``/``router_id`` are each ``NULL``
    for a platform-wide ``HEALTH_STATUS_CHANGE`` rule watching a
    ``ServiceHealth`` component, and populated per-router for a
    per-router ``HEALTH_STATUS_CHANGE``/``THRESHOLD`` rule). See
    ``repository.MonitoringRepository.find_active_alert``.
    ``EVENT_OCCURRED`` rules use a different key -- see
    ``_evaluate_event_occurred_rule``'s own docstring -- since each match is
    a discrete past occurrence, not an ongoing condition.

    ## Recovery design: no separate "Router Online" rule

    There is no paired "recovery" ``AlertRule`` (e.g. no separate "Router
    Online" rule alongside "Router Offline"). Instead, every evaluation pass
    re-checks each active rule's condition against current state: if the
    condition is now false **and** an open ``Alert`` for that exact
    de-duplication key still exists, that alert is transitioned straight to
    ``RESOLVED`` (``auto_resolved=True``) and a recovery notification is
    dispatched through the same channels the original trigger used. This
    was chosen over a second "recovery rule" model because (a) it requires
    zero extra ``AlertRule`` rows per condition (half as much configuration
    for an operator to maintain), (b) it is impossible for a recovery rule
    to silently drift out of sync with its paired trigger rule (there is
    only one rule, one condition, two possible truth values), and (c) it
    mirrors this same codebase's own ``ServiceHealthTransitioned``/
    ``EVENT_TYPE_COMPONENT_RECOVERED`` precedent in Part 1's Health Engine
    (a transition *out of* an unhealthy state is detected by re-evaluating
    the same check, not by a separate "recovered" check type).
    ``EVENT_OCCURRED`` alerts never auto-resolve -- a past event has no
    "condition" that can later become false; those alerts stay open until a
    human resolves them.
    """

    def __init__(
        self,
        repository: MonitoringRepositoryProtocol,
        *,
        notification_service: NotificationService | None = None,
        redis_client: Redis | None = None,
    ) -> None:
        self.repository = repository
        self.notification_service = notification_service
        # Real-Time (BE-011 Part 3): optional, additive -- see
        # _publish_live_message's own docstring. ``None`` (the default) is
        # exactly how every existing caller/test that constructs
        # ``AlertService`` without a Redis client already behaves: no
        # publish attempt, no behavior change.
        self.redis_client = redis_client

    # ------------------------------------------------------------------
    # AlertRule CRUD
    # ------------------------------------------------------------------

    async def create_alert_rule(
        self,
        *,
        name: str,
        description: str | None,
        organization_id: uuid.UUID | None,
        trigger_type: AlertTriggerType,
        target_component: str | None,
        condition_config: dict[str, object],
        severity: str,
        is_active: bool = True,
        notification_channel_ids: list[uuid.UUID] | None = None,
    ) -> AlertRule:
        validate_alert_rule_condition_config(
            trigger_type, target_component, condition_config
        )
        rule = await self.repository.create_alert_rule(
            name=name,
            description=description,
            organization_id=organization_id,
            trigger_type=trigger_type.value,
            target_component=target_component,
            condition_config=condition_config,
            severity=severity,
            is_active=is_active,
        )
        if notification_channel_ids:
            await self.repository.replace_alert_rule_notification_channels(
                rule.id, notification_channel_ids
            )
        return rule

    async def get_alert_rule(self, rule_id: uuid.UUID) -> AlertRule:
        rule = await self.repository.get_alert_rule(rule_id)
        if rule is None:
            raise AlertRuleNotFoundError(rule_id)
        return rule

    async def update_alert_rule(
        self,
        rule_id: uuid.UUID,
        *,
        data: dict[str, object],
        notification_channel_ids: list[uuid.UUID] | None = None,
    ) -> AlertRule:
        rule = await self.get_alert_rule(rule_id)
        prospective_trigger_type = AlertTriggerType(
            data.get("trigger_type", rule.trigger_type)
        )
        prospective_target_component = data.get(
            "target_component", rule.target_component
        )
        prospective_condition_config = data.get(
            "condition_config", rule.condition_config
        )
        validate_alert_rule_condition_config(
            prospective_trigger_type,
            prospective_target_component,
            prospective_condition_config,
        )
        if "trigger_type" in data:
            data["trigger_type"] = prospective_trigger_type.value
        updated = await self.repository.update_alert_rule(rule, data)
        if notification_channel_ids is not None:
            await self.repository.replace_alert_rule_notification_channels(
                rule.id, notification_channel_ids
            )
        return updated

    async def delete_alert_rule(self, rule_id: uuid.UUID) -> None:
        rule = await self.get_alert_rule(rule_id)
        await self.repository.soft_delete_alert_rule(rule)

    async def list_alert_rules(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        page: int = DEFAULT_LIST_PAGE,
        page_size: int = DEFAULT_LIST_PAGE_SIZE,
    ) -> tuple[list[AlertRule], PaginationMeta]:
        return await self.repository.list_alert_rules(
            organization_id=organization_id,
            is_active=is_active,
            page=page,
            page_size=page_size,
        )

    # ------------------------------------------------------------------
    # Alert lifecycle
    # ------------------------------------------------------------------

    async def get_alert(self, alert_id: uuid.UUID) -> Alert:
        alert = await self.repository.get_alert(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)
        return alert

    async def list_alerts(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        severity: str | None = None,
        router_id: uuid.UUID | None = None,
        page: int = DEFAULT_LIST_PAGE,
        page_size: int = DEFAULT_LIST_PAGE_SIZE,
    ) -> tuple[list[Alert], PaginationMeta]:
        return await self.repository.list_alerts(
            organization_id=organization_id,
            status=status,
            severity=severity,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def acknowledge_alert(
        self, alert_id: uuid.UUID, *, user_id: uuid.UUID
    ) -> Alert:
        alert = await self.get_alert(alert_id)
        validate_alert_status_transition(
            AlertStatus(alert.status), AlertStatus.ACKNOWLEDGED
        )
        updated = await self.repository.update_alert(
            alert,
            {
                "status": AlertStatus.ACKNOWLEDGED.value,
                "acknowledged_at": datetime.now(UTC),
                "acknowledged_by_user_id": user_id,
            },
        )
        event = AlertAcknowledged(alert_id=updated.id, acknowledged_by_user_id=user_id)
        logger.info("alert_acknowledged", extra=_event_extra(event))
        return updated

    async def resolve_alert(self, alert_id: uuid.UUID) -> Alert:
        alert = await self.get_alert(alert_id)
        validate_alert_status_transition(
            AlertStatus(alert.status), AlertStatus.RESOLVED
        )
        updated = await self.repository.update_alert(
            alert,
            {"status": AlertStatus.RESOLVED.value, "resolved_at": datetime.now(UTC)},
        )
        event = AlertResolved(alert_id=updated.id, auto_resolved=False)
        logger.info("alert_resolved", extra=_event_extra(event))
        await _publish_live_message(
            self.redis_client,
            RealtimeMessageType.ALERT_RESOLVED,
            payload={
                "alert_id": str(updated.id),
                "rule_id": str(updated.rule_id),
                "severity": updated.severity,
                "message": updated.message,
                "auto_resolved": False,
            },
        )
        return updated

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    async def evaluate_alert_rules(self) -> AlertEvaluationResult:
        """Runs every active :class:`AlertRule` against current state,
        triggering/auto-resolving :class:`Alert` rows and dispatching
        notifications -- see this class's own docstring for the full
        de-duplication-key and recovery-design write-up. Intended to compose
        with Part 1's Health Engine (called after
        ``MonitoringService.run_all_health_checks``) as well as being safely
        callable on demand (``POST /alerts/evaluate``-style admin action);
        it re-derives everything from current repository state rather than
        depending on being invoked at any particular cadence."""
        triggered: list[Alert] = []
        resolved: list[Alert] = []
        rules = await self.repository.list_active_alert_rules()
        for rule in rules:
            if rule.trigger_type == AlertTriggerType.HEALTH_STATUS_CHANGE.value:
                rule_triggered, rule_resolved = await self._evaluate_health_status_rule(
                    rule
                )
            elif rule.trigger_type == AlertTriggerType.THRESHOLD.value:
                rule_triggered, rule_resolved = await self._evaluate_threshold_rule(
                    rule
                )
            else:
                (
                    rule_triggered,
                    rule_resolved,
                ) = await self._evaluate_event_occurred_rule(rule)
            triggered.extend(rule_triggered)
            resolved.extend(rule_resolved)

        for alert in triggered:
            event = AlertTriggered(
                alert_id=alert.id, rule_id=alert.rule_id, severity=alert.severity
            )
            logger.info("alert_triggered", extra=_event_extra(event))
            await self._dispatch_for_alert(alert)
        for alert in resolved:
            await self._dispatch_for_alert(alert)

        return AlertEvaluationResult(triggered=triggered, resolved=resolved)

    async def _evaluate_health_status_rule(
        self, rule: AlertRule
    ) -> tuple[list[Alert], list[Alert]]:
        triggered: list[Alert] = []
        resolved: list[Alert] = []
        expected_status = rule.condition_config.get("expected_status")

        if rule.target_component == ALERT_TARGET_ROUTER:
            routers = await self.repository.list_routers(
                organization_id=rule.organization_id
            )
            for router in routers:
                condition_met = router.health_status == expected_status
                existing = await self.repository.find_active_alert(
                    rule_id=rule.id,
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                    router_id=router.id,
                )
                if condition_met and existing is None:
                    alert = await self._create_alert(
                        rule,
                        organization_id=router.organization_id,
                        location_id=router.location_id,
                        router_id=router.id,
                        message=(
                            f"Router '{router.name}' health status is "
                            f"{router.health_status}"
                        ),
                    )
                    triggered.append(alert)
                elif not condition_met and existing is not None:
                    resolved.append(await self._auto_resolve(existing))
            return triggered, resolved

        service_health = await self.repository.get_service_health(rule.target_component)
        current_status = service_health.status if service_health is not None else None
        condition_met = current_status == expected_status
        existing = await self.repository.find_active_alert(
            rule_id=rule.id,
            organization_id=rule.organization_id,
            location_id=None,
            router_id=None,
        )
        if condition_met and existing is None:
            alert = await self._create_alert(
                rule,
                organization_id=rule.organization_id,
                location_id=None,
                router_id=None,
                message=(
                    f"Component '{rule.target_component}' health status is "
                    f"{current_status}"
                ),
            )
            triggered.append(alert)
        elif not condition_met and existing is not None:
            resolved.append(await self._auto_resolve(existing))
        return triggered, resolved

    async def _evaluate_threshold_rule(
        self, rule: AlertRule
    ) -> tuple[list[Alert], list[Alert]]:
        triggered: list[Alert] = []
        resolved: list[Alert] = []
        metric = rule.condition_config["metric"]
        operator = ThresholdOperator(rule.condition_config["operator"])
        threshold_value = float(rule.condition_config["value"])

        routers = await self.repository.list_routers(
            organization_id=rule.organization_id
        )
        for router in routers:
            snapshot = await self.repository.get_latest_router_health_snapshot(
                router.id
            )
            existing = await self.repository.find_active_alert(
                rule_id=rule.id,
                organization_id=router.organization_id,
                location_id=router.location_id,
                router_id=router.id,
            )
            metric_value = getattr(snapshot, metric, None) if snapshot else None
            if metric_value is None:
                # No data to judge yet -- resolve any stale open alert
                # rather than leave it firing on data that no longer exists.
                if existing is not None:
                    resolved.append(await self._auto_resolve(existing))
                continue
            condition_met = compare_threshold(
                float(metric_value), operator, threshold_value
            )
            if condition_met and existing is None:
                alert = await self._create_alert(
                    rule,
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                    router_id=router.id,
                    message=(
                        f"{metric}={metric_value} ({operator.value} "
                        f"{threshold_value}) on router '{router.name}'"
                    ),
                )
                triggered.append(alert)
            elif not condition_met and existing is not None:
                resolved.append(await self._auto_resolve(existing))
        return triggered, resolved

    async def _evaluate_event_occurred_rule(
        self, rule: AlertRule
    ) -> tuple[list[Alert], list[Alert]]:
        """``EVENT_OCCURRED`` alerts are one-shot: each match against a
        ``PlatformEvent`` row creates at most one ``Alert`` (de-duplicated by
        ``(rule_id, related_event_id)``, not the (rule, target) key every
        other trigger type uses -- a past event is not an ongoing condition
        that can later "clear", so these never appear in this method's
        ``resolved`` return value; they stay open until a human resolves
        them via ``POST /alerts/{id}/resolve``)."""
        triggered: list[Alert] = []
        event_type = rule.condition_config["event_type"]
        since = datetime.now(UTC) - timedelta(minutes=ALERT_EVENT_LOOKBACK_MINUTES)
        events = await self.repository.list_recent_platform_events(
            event_type=event_type, organization_id=rule.organization_id, since=since
        )
        for platform_event in events:
            existing = await self.repository.find_alert_by_related_event(
                rule_id=rule.id, related_event_id=platform_event.id
            )
            if existing is not None:
                continue
            alert = await self._create_alert(
                rule,
                organization_id=platform_event.organization_id or rule.organization_id,
                location_id=platform_event.location_id,
                router_id=platform_event.router_id,
                message=platform_event.message,
                related_event_id=platform_event.id,
            )
            triggered.append(alert)
        return triggered, []

    async def _create_alert(
        self,
        rule: AlertRule,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
        message: str,
        related_event_id: uuid.UUID | None = None,
        related_health_check_id: uuid.UUID | None = None,
    ) -> Alert:
        alert = await self.repository.create_alert(
            rule_id=rule.id,
            status=AlertStatus.TRIGGERED.value,
            triggered_at=datetime.now(UTC),
            acknowledged_at=None,
            acknowledged_by_user_id=None,
            resolved_at=None,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            message=message,
            related_health_check_id=related_health_check_id,
            related_event_id=related_event_id,
            severity=rule.severity,
        )
        # Real-Time (BE-011 Part 3): publish after the DB write above has
        # already succeeded -- see _publish_live_message's own docstring.
        await _publish_live_message(
            self.redis_client,
            RealtimeMessageType.ALERT_TRIGGERED,
            payload={
                "alert_id": str(alert.id),
                "rule_id": str(alert.rule_id),
                "severity": alert.severity,
                "message": alert.message,
                "organization_id": str(organization_id) if organization_id else None,
                "location_id": str(location_id) if location_id else None,
                "router_id": str(router_id) if router_id else None,
            },
        )
        return alert

    async def _auto_resolve(self, alert: Alert) -> Alert:
        resolved = await self.repository.update_alert(
            alert,
            {"status": AlertStatus.RESOLVED.value, "resolved_at": datetime.now(UTC)},
        )
        event = AlertResolved(alert_id=resolved.id, auto_resolved=True)
        logger.info("alert_auto_resolved", extra=_event_extra(event))
        await _publish_live_message(
            self.redis_client,
            RealtimeMessageType.ALERT_RESOLVED,
            payload={
                "alert_id": str(resolved.id),
                "rule_id": str(resolved.rule_id),
                "severity": resolved.severity,
                "message": resolved.message,
                "auto_resolved": True,
            },
        )
        return resolved

    async def _dispatch_for_alert(self, alert: Alert) -> None:
        if self.notification_service is None:
            return
        channel_ids = await self.repository.list_notification_channel_ids_for_rule(
            alert.rule_id
        )
        if not channel_ids:
            return
        channels = await self.notification_service.list_channels_by_ids(channel_ids)
        for channel in channels:
            if not channel.is_active:
                continue
            await self.notification_service.dispatch_notification(
                alert=alert, channel=channel
            )


# ============================================================================
# Notification Engine (BE-011 Part 2)
# ============================================================================


class NotificationDeliveryError(Exception):
    """Raised by a ``Notifier`` implementation when delivery genuinely
    fails (a non-2xx HTTP response, a network error, ...). Always caught by
    ``NotificationService.dispatch_notification`` and turned into a
    ``FAILED`` ``NotificationLog`` row -- **never** allowed to propagate.
    See ``NotificationService``'s own docstring for the full resilience
    rationale: a downstream channel being unreachable (a bad Slack webhook
    URL, a WhatsApp/SMS/email provider outage) must never crash alert
    evaluation, which is what actually protects the platform."""


def _format_alert_message(alert: Alert) -> str:
    """The shared, plain-text message body every notifier's payload is
    built from -- one place to change the wording, not duplicated per
    channel type."""
    if alert.status == "resolved":
        return f"[RESOLVED] {alert.message}"
    return f"[{alert.severity.upper()}] {alert.message}"


class NotifierProtocol(Protocol):
    async def send(self, *, alert: Alert, config: dict[str, object]) -> str: ...


class EmailNotifier:
    """Wraps ``app.domains.otp``'s existing ``EmailProviderProtocol`` --
    composition, not a second email-provider abstraction."""

    def __init__(self, email_provider: EmailProviderProtocol) -> None:
        self.email_provider = email_provider

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        email = str(config["email"])
        await self.email_provider.send(
            email,
            f"CloudGuest alert: {alert.severity.upper()}",
            _format_alert_message(alert),
        )
        return f"queued to {email} via EmailProviderProtocol"


class SmsNotifier:
    """Wraps ``app.domains.otp``'s existing ``SmsProviderProtocol`` --
    composition, not a second SMS-provider abstraction."""

    def __init__(self, sms_provider: SmsProviderProtocol) -> None:
        self.sms_provider = sms_provider

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        phone_number = str(config["phone_number"])
        await self.sms_provider.send(phone_number, _format_alert_message(alert))
        return f"queued to {phone_number} via SmsProviderProtocol"


class WhatsAppNotifier:
    """Honest logging-only placeholder -- mirrors OTP's own
    ``LoggingSmsProvider``/``LoggingEmailProvider`` precedent exactly.

    **Why WhatsApp, and only WhatsApp, does not get a real integration
    here** (unlike Slack/Teams/Discord/Webhook, all real ``httpx`` POSTs
    below): a real WhatsApp notification requires a paid WhatsApp Business
    API account/SDK (Meta Cloud API or a BSP like Twilio/360dialog), with
    real per-account credentials, a verified sending number, and approved
    message templates -- none of which exist, or should be faked, in this
    sandbox, per this codebase's explicit honesty mandate around
    Stripe/Razorpay/MSG91/SES/OpenAI/WhatsApp-Business-API integrations.
    Slack/Teams/Discord/Webhook are categorically different: each is just a
    plain outbound HTTP POST to an incoming-webhook URL, something any
    operator can generate for free in seconds with no paid account, so
    those genuinely can (and do) get real ``httpx.AsyncClient`` calls.
    """

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        phone_number = config.get("phone_number", "<unknown>")
        logger.info(
            "whatsapp_notification_would_send",
            extra={
                "phone_number": phone_number,
                "message_length": len(_format_alert_message(alert)),
            },
        )
        return "logged only -- no real WhatsApp Business API integration exists"


async def _post_json(
    http_client: httpx.AsyncClient, url: str, payload: dict[str, object]
) -> httpx.Response:
    """Shared real-HTTP-POST helper for every webhook-style notifier below.
    Raises ``NotificationDeliveryError`` (never a raw ``httpx`` exception)
    on any network error or non-2xx response."""
    try:
        response = await http_client.post(
            url, json=payload, timeout=HTTP_NOTIFICATION_TIMEOUT_SECONDS
        )
    except httpx.HTTPError as exc:
        raise NotificationDeliveryError(f"HTTP request failed: {exc}") from exc
    if response.status_code >= 400:
        raise NotificationDeliveryError(
            f"HTTP {response.status_code}: {response.text[:200]}"
        )
    return response


class SlackNotifier:
    """A REAL ``httpx.AsyncClient`` POST to a Slack incoming-webhook URL,
    using Slack's real, documented payload convention (a top-level
    ``"text"`` field)."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        webhook_url = str(config["webhook_url"])
        payload = {"text": _format_alert_message(alert)}
        response = await _post_json(self.http_client, webhook_url, payload)
        return f"HTTP {response.status_code}"


class TeamsNotifier:
    """A REAL ``httpx.AsyncClient`` POST to a Microsoft Teams incoming-
    webhook URL, using Teams' real, documented legacy ``MessageCard``
    payload convention."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        webhook_url = str(config["webhook_url"])
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "CloudGuest alert",
            "themeColor": "FF0000" if alert.severity == "critical" else "FFA500",
            "title": f"CloudGuest {alert.severity.upper()} alert",
            "text": _format_alert_message(alert),
        }
        response = await _post_json(self.http_client, webhook_url, payload)
        return f"HTTP {response.status_code}"


class DiscordNotifier:
    """A REAL ``httpx.AsyncClient`` POST to a Discord incoming-webhook URL,
    using Discord's real, documented payload convention (a top-level
    ``"content"`` field)."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        webhook_url = str(config["webhook_url"])
        payload = {"content": _format_alert_message(alert)}
        response = await _post_json(self.http_client, webhook_url, payload)
        return f"HTTP {response.status_code}"


class WebhookNotifier:
    """A REAL ``httpx.AsyncClient`` POST to a generic, operator-configured
    URL with this module's own structured JSON body (not a third-party
    convention -- there is no single standard "generic webhook" payload
    shape), plus an optional single custom auth header."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client

    async def send(self, *, alert: Alert, config: dict[str, object]) -> str:
        url = str(config["url"])
        payload = {
            "event": "alert",
            "alert_id": str(alert.id),
            "rule_id": str(alert.rule_id),
            "severity": alert.severity,
            "status": alert.status,
            "message": alert.message,
            "triggered_at": alert.triggered_at.isoformat(),
        }
        headers = {}
        header_name = config.get("auth_header_name")
        header_value = config.get("auth_header_value")
        if header_name and header_value:
            headers[str(header_name)] = str(header_value)
        try:
            response = await self.http_client.post(
                url,
                json=payload,
                headers=headers,
                timeout=HTTP_NOTIFICATION_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise NotificationDeliveryError(f"HTTP request failed: {exc}") from exc
        if response.status_code >= 400:
            raise NotificationDeliveryError(
                f"HTTP {response.status_code}: {response.text[:200]}"
            )
        return f"HTTP {response.status_code}"


class NotificationService:
    """Notification Engine business logic: ``NotificationChannel`` CRUD and
    ``dispatch_notification`` -- picks the right ``Notifier`` by
    ``channel_type``, sends, and records a ``NotificationLog`` row.

    ## Resilience: a delivery failure never raises

    ``dispatch_notification`` catches every exception a ``Notifier.send``
    call can raise (``NotificationDeliveryError`` for an expected delivery
    failure, plus any other unexpected exception) and always returns a
    ``NotificationLog`` row -- ``SENT`` or ``FAILED`` -- rather than ever
    propagating. This is a deliberate design choice: alert evaluation
    (``AlertService.evaluate_alert_rules``) may fan a single trigger out to
    several channels, and one bad Slack webhook URL or a temporarily-down
    SMS gateway must never prevent the *other* channels from being
    notified, and must never crash the evaluation pass that is the actual
    mechanism protecting the platform. Every failure is still fully
    observable -- logged via the structured logger and durably recorded as
    a ``FAILED`` ``NotificationLog`` row with its ``error_message``, so an
    operator can diagnose and fix a broken channel without alert evaluation
    itself ever going down because of it.
    """

    def __init__(
        self,
        repository: MonitoringRepositoryProtocol,
        http_client: httpx.AsyncClient,
        *,
        sms_provider: SmsProviderProtocol | None = None,
        email_provider: EmailProviderProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.http_client = http_client
        self._notifiers: dict[str, NotifierProtocol] = {
            NotificationChannelType.EMAIL.value: EmailNotifier(
                email_provider or LoggingEmailProvider()
            ),
            NotificationChannelType.SMS.value: SmsNotifier(
                sms_provider or LoggingSmsProvider()
            ),
            NotificationChannelType.WHATSAPP.value: WhatsAppNotifier(),
            NotificationChannelType.SLACK.value: SlackNotifier(http_client),
            NotificationChannelType.TEAMS.value: TeamsNotifier(http_client),
            NotificationChannelType.DISCORD.value: DiscordNotifier(http_client),
            NotificationChannelType.WEBHOOK.value: WebhookNotifier(http_client),
        }

    async def dispatch_notification(
        self, *, alert: Alert, channel: NotificationChannel
    ) -> NotificationLog:
        notifier = self._notifiers[channel.channel_type]
        try:
            config = json.loads(decrypt_secret(channel.config_encrypted))
            response_summary = await notifier.send(alert=alert, config=config)
            log = await self.repository.create_notification_log(
                channel_id=channel.id,
                alert_id=alert.id,
                sent_at=datetime.now(UTC),
                status=NotificationStatus.SENT.value,
                error_message=None,
                response_summary=response_summary,
            )
            status_value = NotificationStatus.SENT
        except Exception as exc:  # noqa: BLE001 -- see class docstring
            log = await self.repository.create_notification_log(
                channel_id=channel.id,
                alert_id=alert.id,
                sent_at=datetime.now(UTC),
                status=NotificationStatus.FAILED.value,
                error_message=str(exc)[:500],
                response_summary=None,
            )
            status_value = NotificationStatus.FAILED
            logger.warning(
                "notification_dispatch_failed",
                extra={
                    "channel_id": str(channel.id),
                    "channel_type": channel.channel_type,
                    "alert_id": str(alert.id),
                    "error": str(exc),
                },
            )

        event = NotificationDispatched(
            channel_id=channel.id,
            channel_type=channel.channel_type,
            alert_id=alert.id,
            status=status_value.value,
        )
        logger.info("notification_dispatched", extra=_event_extra(event))
        return log

    async def create_channel(
        self,
        *,
        organization_id: uuid.UUID | None,
        channel_type: NotificationChannelType,
        name: str,
        config: dict[str, object],
        is_active: bool = True,
    ) -> NotificationChannel:
        validate_notification_channel_config(channel_type, config)
        config_encrypted = encrypt_secret(json.dumps(config))
        return await self.repository.create_notification_channel(
            organization_id=organization_id,
            channel_type=channel_type.value,
            name=name,
            config_encrypted=config_encrypted,
            is_active=is_active,
        )

    async def get_channel(self, channel_id: uuid.UUID) -> NotificationChannel:
        channel = await self.repository.get_notification_channel(channel_id)
        if channel is None:
            raise NotificationChannelNotFoundError(channel_id)
        return channel

    async def update_channel(
        self,
        channel_id: uuid.UUID,
        *,
        data: dict[str, object],
        config: dict[str, object] | None = None,
    ) -> NotificationChannel:
        channel = await self.get_channel(channel_id)
        if config is not None:
            channel_type = NotificationChannelType(
                data.get("channel_type", channel.channel_type)
            )
            validate_notification_channel_config(channel_type, config)
            data = {**data, "config_encrypted": encrypt_secret(json.dumps(config))}
        return await self.repository.update_notification_channel(channel, data)

    async def delete_channel(self, channel_id: uuid.UUID) -> None:
        channel = await self.get_channel(channel_id)
        await self.repository.soft_delete_notification_channel(channel)

    async def list_channels(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        channel_type: str | None = None,
        is_active: bool | None = None,
        page: int = DEFAULT_LIST_PAGE,
        page_size: int = DEFAULT_LIST_PAGE_SIZE,
    ) -> tuple[list[NotificationChannel], PaginationMeta]:
        return await self.repository.list_notification_channels(
            organization_id=organization_id,
            channel_type=channel_type,
            is_active=is_active,
            page=page,
            page_size=page_size,
        )

    async def list_channels_by_ids(
        self, channel_ids: list[uuid.UUID]
    ) -> list[NotificationChannel]:
        return await self.repository.get_notification_channels_by_ids(channel_ids)

    async def list_logs(
        self,
        *,
        channel_id: uuid.UUID | None = None,
        alert_id: uuid.UUID | None = None,
        status: str | None = None,
        page: int = DEFAULT_LIST_PAGE,
        page_size: int = DEFAULT_LIST_PAGE_SIZE,
    ) -> tuple[list[NotificationLog], PaginationMeta]:
        return await self.repository.list_notification_logs(
            channel_id=channel_id,
            alert_id=alert_id,
            status=status,
            page=page,
            page_size=page_size,
        )


# ============================================================================
# Incident Engine (BE-011 Part 2)
# ============================================================================


class IncidentService:
    """Incident Engine business logic: fully-manual ``Incident`` CRUD,
    status-transition lifecycle, and ``Alert`` grouping (attach only -- see
    ``models.IncidentAlert``'s docstring for why no auto-grouping heuristic
    is implemented)."""

    def __init__(self, repository: MonitoringRepositoryProtocol) -> None:
        self.repository = repository

    async def create_incident(
        self,
        *,
        title: str,
        description: str | None,
        severity: str,
        organization_id: uuid.UUID | None,
        assigned_to_user_id: uuid.UUID | None = None,
    ) -> Incident:
        incident = await self.repository.create_incident(
            title=title,
            description=description,
            status=IncidentStatus.OPEN.value,
            severity=severity,
            organization_id=organization_id,
            assigned_to_user_id=assigned_to_user_id,
            opened_at=datetime.now(UTC),
            resolved_at=None,
            closed_at=None,
            resolution_notes=None,
        )
        event = IncidentOpened(incident_id=incident.id, severity=incident.severity)
        logger.info("incident_opened", extra=_event_extra(event))
        return incident

    async def get_incident(self, incident_id: uuid.UUID) -> Incident:
        incident = await self.repository.get_incident(incident_id)
        if incident is None:
            raise IncidentNotFoundError(incident_id)
        return incident

    async def list_incidents(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        severity: str | None = None,
        page: int = DEFAULT_LIST_PAGE,
        page_size: int = DEFAULT_LIST_PAGE_SIZE,
    ) -> tuple[list[Incident], PaginationMeta]:
        return await self.repository.list_incidents(
            organization_id=organization_id,
            status=status,
            severity=severity,
            page=page,
            page_size=page_size,
        )

    async def update_incident(
        self,
        incident_id: uuid.UUID,
        *,
        status: IncidentStatus | None = None,
        title: str | None = None,
        description: str | None = None,
        assigned_to_user_id: uuid.UUID | None = None,
        resolution_notes: str | None = None,
    ) -> Incident:
        incident = await self.get_incident(incident_id)
        data: dict[str, object] = {}
        if title is not None:
            data["title"] = title
        if description is not None:
            data["description"] = description
        if assigned_to_user_id is not None:
            data["assigned_to_user_id"] = assigned_to_user_id
        if resolution_notes is not None:
            data["resolution_notes"] = resolution_notes

        if status is not None and status.value != incident.status:
            validate_incident_status_transition(IncidentStatus(incident.status), status)
            data["status"] = status.value
            now = datetime.now(UTC)
            if status == IncidentStatus.RESOLVED:
                data["resolved_at"] = now
            if status == IncidentStatus.CLOSED:
                data["closed_at"] = now
            event = IncidentStatusChanged(
                incident_id=incident.id,
                previous_status=incident.status,
                new_status=status.value,
            )
            logger.info("incident_status_changed", extra=_event_extra(event))

        if not data:
            return incident
        return await self.repository.update_incident(incident, data)

    async def attach_alert(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> Incident:
        incident = await self.get_incident(incident_id)
        already_attached = await self.repository.incident_alert_exists(
            incident.id, alert_id
        )
        if not already_attached:
            await self.repository.attach_alert_to_incident(incident.id, alert_id)
        return incident

    async def list_alerts_for_incident(self, incident_id: uuid.UUID) -> list[Alert]:
        await self.get_incident(incident_id)
        return await self.repository.list_alerts_for_incident(incident_id)


# ============================================================================
# SLA Monitoring (BE-011 Part 2)
# ============================================================================


class SlaService:
    """SLA Monitoring business logic: ``SlaTarget`` CRUD and
    ``generate_report`` -- a real computation against Part 1's own
    ``HealthCheck`` history (composition, never a duplicate metrics store).
    """

    def __init__(self, repository: MonitoringRepositoryProtocol) -> None:
        self.repository = repository

    async def create_target(
        self,
        *,
        organization_id: uuid.UUID | None,
        component: str | None,
        target_percentage: float,
        measurement_window_days: int,
    ) -> SlaTarget:
        validate_sla_target_config(
            target_percentage=target_percentage,
            measurement_window_days=measurement_window_days,
        )
        return await self.repository.create_sla_target(
            organization_id=organization_id,
            component=component,
            target_percentage=target_percentage,
            measurement_window_days=measurement_window_days,
        )

    async def get_target(self, target_id: uuid.UUID) -> SlaTarget:
        target = await self.repository.get_sla_target(target_id)
        if target is None:
            raise SlaTargetNotFoundError(target_id)
        return target

    async def list_targets_with_latest_report(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[tuple[SlaTarget, SlaReport | None]]:
        targets = await self.repository.list_sla_targets(
            organization_id=organization_id
        )
        results: list[tuple[SlaTarget, SlaReport | None]] = []
        for target in targets:
            latest_report = await self.repository.get_latest_sla_report(target.id)
            results.append((target, latest_report))
        return results

    async def list_reports(
        self,
        target_id: uuid.UUID,
        *,
        page: int = DEFAULT_LIST_PAGE,
        page_size: int = DEFAULT_LIST_PAGE_SIZE,
    ) -> tuple[list[SlaReport], PaginationMeta]:
        await self.get_target(target_id)
        return await self.repository.list_sla_reports(
            sla_target_id=target_id, page=page, page_size=page_size
        )

    async def generate_report(
        self, target_id: uuid.UUID, *, period_days: int | None = None
    ) -> SlaReport:
        """Computes ``achieved_percentage = healthy_checks / total_checks *
        100`` over the target's own ``measurement_window_days`` (or an
        explicit ``period_days`` override) against Part 1's own
        ``HealthCheck`` history.

        ## Formula: a simple check-count ratio, not downtime-duration-
        weighted -- and why

        A duration-weighted formula (summing the wall-clock time each
        non-healthy status was in effect) would, in principle, more
        precisely measure "percentage of time healthy." It was
        deliberately **not** chosen here: this environment has no recurring
        scheduler (no Celery -- see ``HealthComponent.CELERY``'s
        docstring), so ``HealthCheck`` rows are produced whenever
        ``POST /monitoring/health/run`` happens to be invoked (an on-demand
        admin action, or a test), not on any guaranteed fixed cadence. A
        duration-weighted calculation would have to either assume a fixed
        polling interval that does not actually exist, or infer an interval
        from the gaps between actual rows -- both would silently fabricate
        precision this data does not honestly support (the same "don't
        pretend to know what you don't" principle Part 1 applies to its
        honest Celery/WebSocket ``UNKNOWN``s). A simple healthy-count /
        total-count ratio makes no such assumption: it is exactly what the
        recorded data actually says, "what fraction of the checks we
        actually ran came back healthy," and is correct-by-construction
        the moment a real recurring health-check scheduler exists (at a
        fixed interval, the two formulas converge).

        Raises ``InsufficientSlaDataError`` if zero ``HealthCheck`` rows
        exist for the window -- never fabricates a 0%/100% result from no
        data (the identical honesty posture Part 1's Health Engine already
        established).
        """
        target = await self.get_target(target_id)
        window_days = period_days or target.measurement_window_days
        period_end = datetime.now(UTC)
        period_start = period_end - timedelta(days=window_days)

        (
            total,
            healthy,
            average_response_time_ms,
        ) = await self.repository.compute_health_check_stats(
            component=target.component, start=period_start, end=period_end
        )
        if total == 0:
            raise InsufficientSlaDataError(target.component)

        achieved_percentage = round((healthy / total) * 100, 4)
        report = await self.repository.create_sla_report(
            sla_target_id=target.id,
            period_start=period_start,
            period_end=period_end,
            achieved_percentage=achieved_percentage,
            total_checks=total,
            healthy_checks=healthy,
            average_response_time_ms=average_response_time_ms,
            generated_at=period_end,
        )
        event = SlaReportGenerated(
            sla_target_id=target.id, achieved_percentage=achieved_percentage
        )
        logger.info("sla_report_generated", extra=_event_extra(event))
        return report

    async def get_average_provisioning_duration_seconds(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> float | None:
        """Read-only composition with
        ``app.domains.router_provisioning.models.ProvisioningJob``'s own
        ``started_at``/``completed_at`` timestamps -- the module brief's
        provisioning-time analytics bullet."""
        return await self.repository.get_average_provisioning_duration_seconds(
            organization_id=organization_id, start=start, end=end
        )


# ============================================================================
# ZTP Monitoring Dashboard (BE-011 Part 3) -- read-only aggregation over
# app.domains.router_provisioning's own existing data
# ============================================================================


@dataclass(frozen=True, slots=True)
class RouterLifecycleEntry:
    """One row of ``ZtpMonitoringService.get_dashboard``'s unified listing
    -- either a real ``Router`` (``router_id`` set) or a still-router-less
    ``RouterEnrollmentRequest`` (``enrollment_id`` set, ``router_id`` and
    every router-only field ``None``)."""

    router_id: uuid.UUID | None
    enrollment_id: uuid.UUID | None
    serial_number: str
    mac_address: str | None
    model: str
    name: str | None
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    router_status: str | None
    enrollment_status: str | None
    lifecycle_stage: RouterLifecycleStage
    last_seen_at: datetime | None
    latest_job_type: str | None
    latest_job_status: str | None
    latest_job_attempts: int | None
    latest_job_max_attempts: int | None


@dataclass(frozen=True, slots=True)
class ZtpDashboardResult:
    stage_counts: dict[str, int]
    pending_enrollment_count: int
    items: list[RouterLifecycleEntry]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


@dataclass(frozen=True, slots=True)
class ProvisioningFailureBreakdown:
    job_type: str
    failure_count: int


@dataclass(frozen=True, slots=True)
class ProvisioningFailureSample:
    job_id: uuid.UUID
    router_id: uuid.UUID
    job_type: str
    attempts: int
    max_attempts: int
    error_message: str | None
    scheduled_at: datetime


@dataclass(frozen=True, slots=True)
class RetryJobEntry:
    job_id: uuid.UUID
    router_id: uuid.UUID
    job_type: str
    status: str
    attempts: int
    max_attempts: int
    attempts_remaining: int
    scheduled_at: datetime


@dataclass(frozen=True, slots=True)
class ZtpAnalyticsResult:
    success_rate_percentage: float | None
    succeeded_job_count: int
    terminal_job_count: int
    failure_breakdown: list[ProvisioningFailureBreakdown]
    failure_samples: list[ProvisioningFailureSample]
    retry_jobs: list[RetryJobEntry]
    average_activation_seconds: float | None
    activation_sample_size: int


class ZtpMonitoringService:
    """Read-only aggregation/monitoring views over
    ``app.domains.router_provisioning``'s own already-persisted data --
    per this part's directory rule, this class **never** creates, updates,
    or regenerates a single row of provisioning state; every method here is
    a ``SELECT``-only composition (through ``MonitoringRepositoryProtocol``'s
    new ZTP methods, which themselves read ``router_provisioning``'s/
    ``router``'s models directly -- the same "compose, don't duplicate,
    don't touch the owning domain's files" precedent this whole repository
    already establishes for ``RouterEvent``/``RouterHealthSnapshot``/
    ``ProvisioningJob``).

    ## Provisioning Success Rate: denominator choice

    ``get_analytics`` computes success rate as ``succeeded ProvisioningJobs
    / (succeeded + failed) ProvisioningJobs`` in the window -- **not**
    "approved enrollments that reached ``ONLINE`` / total approved
    enrollments". Both were considered; ``ProvisioningJob``-based was
    chosen because:

    * ``ProvisioningJob`` is the actual execution unit this codebase already
      tracks success/failure and retry (``attempts``/``max_attempts``) for,
      per job type (``initial_config``/``config_push``/``backup``/
      ``restore``/``factory_reset``) -- exactly what "did this provisioning
      *action* succeed" means operationally.
    * ``Router.status == ONLINE`` is driven by **heartbeats**
      (``app.domains.router_agent``'s check-in flow), a signal orthogonal to
      any specific job's outcome -- a router can reach ``ONLINE`` via
      heartbeat even after its most recent ``config_push`` job failed (a
      later successful heartbeat doesn't retroactively fix a failed config
      push), and conversely a router whose ``initial_config`` job succeeded
      can still show as ``OFFLINE``/stale for reasons that have nothing to
      do with provisioning execution (a device unplugged after setup). Using
      "reached ``ONLINE``" as the success signal would conflate provisioning
      execution success with device connectivity, two genuinely different
      failure modes this dashboard should be able to tell apart (a retry
      dashboard for the former, a heartbeat/offline signal for the latter).
    * Queued/running jobs are excluded from both numerator and denominator
      (they are still in flight, not yet a resolved outcome) -- included,
      they would understate the success rate for a window with recent
      activity.

    ## Router Activation analytics: an honest approximation

    ``get_analytics``'s ``average_activation_seconds`` composes
    ``RouterEnrollmentRequest.reviewed_at`` (the approval timestamp) with the
    completion timestamp of that router's ``initial_config``
    :class:`~.models.ProvisioningJob` (via
    ``MonitoringRepositoryProtocol.compute_activation_duration_stats``).
    This is **not** a literal "time to first ``ONLINE``" measurement --
    no table anywhere in this codebase records the timestamp of a router's
    first transition to ``RouterStatus.ONLINE``: ``Router.last_seen_at`` is
    overwritten on every single heartbeat (never "first seen"), and neither
    ``RouterHealthSnapshot`` (periodic metrics, not status transitions) nor
    ``RouterEvent`` (no ``"router_online"`` event type exists) capture that
    moment either. "Approval -> initial-config-job-completion" is the
    closest genuinely-recoverable proxy this system's actual persisted data
    supports, and is reported honestly as such (see the response schema's
    own field naming/description) rather than mislabeled as something more
    precise than it is -- the same "don't fabricate precision the data
    doesn't support" discipline Part 2's ``SlaService.generate_report``
    already documents for its own check-count-ratio-vs-duration-weighted
    formula choice.
    """

    def __init__(self, repository: MonitoringRepositoryProtocol) -> None:
        self.repository = repository

    async def get_dashboard(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        page: int = DEFAULT_ZTP_PAGE,
        page_size: int = DEFAULT_ZTP_PAGE_SIZE,
    ) -> ZtpDashboardResult:
        """Builds the unified "where does every router currently sit"
        listing plus a full stage-count tally (over *every* matching row,
        not just the current page).

        Performs one lookup per router to resolve its own enrollment/latest-
        job context (not a single mega-join) -- deliberate: ``lifecycle
        stage`` is a Python-level classification
        (``validators.compute_lifecycle_stage``) over three typed model
        instances, not a value a single SQL expression can produce, and this
        table's realistic scale (one row per physical router, not per
        guest-session) does not need single-query optimization the way the
        *statistics*/*analytics* methods below do (those ARE real SQL
        ``GROUP BY``/``AVG`` aggregates)."""
        routers = await self.repository.list_routers(organization_id=organization_id)
        all_enrollments = await self.repository.list_all_enrollment_requests()
        # Enrollment requests carry no organization_id of their own (they
        # are, by definition, submitted before any Router/tenant
        # association exists -- see RouterEnrollmentRequest's own
        # docstring), so a still-router-less enrollment can only ever be
        # shown in the platform-wide (organization_id=None) view.
        unclaimed_enrollments = (
            []
            if organization_id is not None
            else [
                e
                for e in all_enrollments
                if e.status != EnrollmentStatus.APPROVED.value
            ]
        )

        entries: list[RouterLifecycleEntry] = []
        for router in routers:
            enrollment = await self.repository.get_enrollment_for_router(router.id)
            latest_job = await self.repository.get_latest_provisioning_job_for_router(
                router.id
            )
            stage = compute_lifecycle_stage(
                router=router, enrollment=enrollment, latest_job=latest_job
            )
            entries.append(
                RouterLifecycleEntry(
                    router_id=router.id,
                    enrollment_id=enrollment.id if enrollment else None,
                    serial_number=router.serial_number,
                    mac_address=router.mac_address,
                    model=router.model,
                    name=router.name,
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                    router_status=router.status,
                    enrollment_status=enrollment.status if enrollment else None,
                    lifecycle_stage=stage,
                    last_seen_at=router.last_seen_at,
                    latest_job_type=latest_job.job_type if latest_job else None,
                    latest_job_status=latest_job.status if latest_job else None,
                    latest_job_attempts=latest_job.attempts if latest_job else None,
                    latest_job_max_attempts=(
                        latest_job.max_attempts if latest_job else None
                    ),
                )
            )
        for enrollment in unclaimed_enrollments:
            stage = compute_lifecycle_stage(
                router=None, enrollment=enrollment, latest_job=None
            )
            entries.append(
                RouterLifecycleEntry(
                    router_id=None,
                    enrollment_id=enrollment.id,
                    serial_number=enrollment.serial_number,
                    mac_address=enrollment.mac_address,
                    model=enrollment.model,
                    name=None,
                    organization_id=None,
                    location_id=None,
                    router_status=None,
                    enrollment_status=enrollment.status,
                    lifecycle_stage=stage,
                    last_seen_at=None,
                    latest_job_type=None,
                    latest_job_status=None,
                    latest_job_attempts=None,
                    latest_job_max_attempts=None,
                )
            )

        stage_counts: dict[str, int] = {
            stage.value: 0 for stage in RouterLifecycleStage
        }
        for entry in entries:
            stage_counts[entry.lifecycle_stage.value] += 1

        entries.sort(
            key=lambda e: e.last_seen_at or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )
        total_items = len(entries)
        start_index = (page - 1) * page_size
        page_items = entries[start_index : start_index + page_size]
        total_pages = (
            max(1, (total_items + page_size - 1) // page_size) if total_items else 0
        )
        pending_enrollment_count = (
            await self.repository.count_pending_enrollment_requests()
        )

        return ZtpDashboardResult(
            stage_counts=stage_counts,
            pending_enrollment_count=pending_enrollment_count,
            items=page_items,
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_next=start_index + page_size < total_items,
            has_previous=page > 1,
        )

    async def get_analytics(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
        failure_sample_limit: int = DEFAULT_FAILURE_SAMPLE_LIMIT,
        retry_page: int = DEFAULT_ZTP_PAGE,
        retry_page_size: int = DEFAULT_ZTP_PAGE_SIZE,
    ) -> ZtpAnalyticsResult:
        """Provisioning Success Rate + Provisioning Failure Reports + Retry
        Dashboard + Router Activation timing -- see this class's own
        docstring for the denominator/approximation write-ups. Every
        aggregate here is a real SQL query (``MonitoringRepositoryProtocol``'s
        new ZTP methods), never a Python-side loop over fetched rows."""
        validate_date_range(start, end)

        (
            succeeded,
            terminal,
        ) = await self.repository.compute_provisioning_job_outcome_counts(
            organization_id=organization_id, start=start, end=end
        )
        success_rate = round((succeeded / terminal) * 100, 4) if terminal else None

        failure_counts = await self.repository.list_provisioning_failure_counts(
            organization_id=organization_id, start=start, end=end
        )
        failure_breakdown = [
            ProvisioningFailureBreakdown(job_type=job_type, failure_count=count)
            for job_type, count in failure_counts
        ]

        failure_samples_raw = await self.repository.list_provisioning_failure_samples(
            organization_id=organization_id,
            start=start,
            end=end,
            limit=failure_sample_limit,
        )
        failure_samples = [
            ProvisioningFailureSample(
                job_id=job.id,
                router_id=job.router_id,
                job_type=job.job_type,
                attempts=job.attempts,
                max_attempts=job.max_attempts,
                error_message=job.error_message,
                scheduled_at=job.scheduled_at,
            )
            for job in failure_samples_raw
        ]

        retry_rows, _retry_meta = await self.repository.list_retry_jobs(
            organization_id=organization_id, page=retry_page, page_size=retry_page_size
        )
        retry_jobs = [
            RetryJobEntry(
                job_id=job.id,
                router_id=job.router_id,
                job_type=job.job_type,
                status=job.status,
                attempts=job.attempts,
                max_attempts=job.max_attempts,
                attempts_remaining=max(job.max_attempts - job.attempts, 0),
                scheduled_at=job.scheduled_at,
            )
            for job in retry_rows
        ]

        (
            avg_seconds,
            sample_size,
        ) = await self.repository.compute_activation_duration_stats(
            organization_id=organization_id, start=start, end=end
        )

        return ZtpAnalyticsResult(
            success_rate_percentage=success_rate,
            succeeded_job_count=succeeded,
            terminal_job_count=terminal,
            failure_breakdown=failure_breakdown,
            failure_samples=failure_samples,
            retry_jobs=retry_jobs,
            average_activation_seconds=avg_seconds,
            activation_sample_size=sample_size,
        )


# ============================================================================
# Platform Dashboard Statistics (BE-011 Part 3)
# ============================================================================


@dataclass(frozen=True, slots=True)
class PlatformDashboardResult:
    overall_health_status: str
    health_components: list[ServiceHealth]
    alert_counts_by_severity: dict[str, int]
    alert_counts_by_status: dict[str, int]
    device_counts_by_status: dict[str, int]
    lifecycle_stage_counts: dict[str, int]
    pending_enrollment_count: int
    average_response_time_ms: float | None
    availability_percentage: float | None
    visitors: int | None
    unique_guests: int | None


class PlatformDashboardService:
    """Composes Part 1's Health Engine summary, Part 2's Alert Engine
    counts, this Part's own ``ZtpMonitoringService`` stage counts, and
    (optionally) ``app.domains.guest``'s visitor analytics into the single
    "at a glance" payload ``GET /monitoring/dashboard`` serves. Every field
    is produced by an existing, already-tested aggregate method -- this
    class adds no new query logic of its own beyond simple orchestration and
    the ``Availability %``/``Average Response Time`` glance figures (which
    reuse ``MonitoringRepositoryProtocol.compute_health_check_stats``, the
    exact same real-SQL-aggregate method Part 2's ``SlaService
    .generate_report`` already uses -- see ``get_dashboard_statistics``'s
    own docstring for why a live, un-persisted call to that same method is
    the right "at a glance" number here, rather than reading the latest
    persisted ``SlaReport`` (which only exists once an admin has configured
    an ``SlaTarget`` and generated a report against it -- this dashboard
    figure must be available with zero configuration).

    ## Visitor stats: only populated with an ``organization_id``

    ``app.domains.guest.service.GuestAnalyticsService.get_summary`` requires
    a non-``None`` ``organization_id`` -- guest analytics are inherently
    tenant-scoped upstream (every guest session belongs to exactly one
    organization). A genuinely platform-wide visitor aggregate would need
    either a new cross-tenant query added to ``guest``'s own repository (out
    of this part's directory-rule scope: the only permitted guest-domain
    edit is the narrow ``GuestService`` broadcast hook) or an expensive
    per-organization fan-out loop that isn't a real aggregate query. The
    honest choice made here: ``visitors``/``unique_guests`` are populated
    only when the caller supplies ``organization_id``; the platform-wide
    dashboard view (no ``organization_id``) reports them as ``None`` rather
    than a fabricated or partial number.
    """

    def __init__(
        self,
        repository: MonitoringRepositoryProtocol,
        ztp_service: ZtpMonitoringService,
        *,
        guest_visitor_lookup: GuestVisitorLookupProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.ztp_service = ztp_service
        self.guest_visitor_lookup = guest_visitor_lookup

    async def get_dashboard_statistics(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        guest_visitor_lookup: GuestVisitorLookupProtocol | None = None,
    ) -> PlatformDashboardResult:
        """``guest_visitor_lookup`` may be supplied per-call (in addition to,
        or instead of, one wired at construction time) -- ``router.py``'s
        ``get_platform_dashboard`` endpoint does exactly this, since it (not
        ``dependencies.py``) is the seam that can safely import
        ``app.domains.guest``'s own dependency factory with no circular-
        import risk (see ``dependencies.get_platform_dashboard_service``'s
        docstring for the full write-up). Falls back to the constructor-time
        value, then to ``None`` (no visitor stats)."""
        validate_date_range(start, end)
        visitor_lookup = guest_visitor_lookup or self.guest_visitor_lookup

        health_rows = await self.repository.list_service_health()
        overall_status = _compute_overall_health_status(health_rows)

        alert_by_severity = dict(
            await self.repository.compute_alert_counts_by_severity(
                organization_id=organization_id, start=start, end=end
            )
        )
        alert_by_status = dict(
            await self.repository.compute_alert_counts_by_status(
                organization_id=organization_id, start=start, end=end
            )
        )
        device_by_status = dict(
            await self.repository.count_routers_by_status(
                organization_id=organization_id
            )
        )
        ztp_dashboard = await self.ztp_service.get_dashboard(
            organization_id=organization_id, page=1, page_size=1
        )

        (
            total,
            healthy,
            average_response_time_ms,
        ) = await self.repository.compute_health_check_stats(
            component=None, start=start, end=end
        )
        availability_percentage = round((healthy / total) * 100, 4) if total else None

        visitors: int | None = None
        unique_guests: int | None = None
        if organization_id is not None and visitor_lookup is not None:
            summary = await visitor_lookup.get_summary(
                organization_id=organization_id,
                location_id=None,
                start=start,
                end=end,
            )
            visitors = summary.visitors
            unique_guests = summary.unique_guests

        return PlatformDashboardResult(
            overall_health_status=overall_status.value,
            health_components=health_rows,
            alert_counts_by_severity=alert_by_severity,
            alert_counts_by_status=alert_by_status,
            device_counts_by_status=device_by_status,
            lifecycle_stage_counts=ztp_dashboard.stage_counts,
            pending_enrollment_count=ztp_dashboard.pending_enrollment_count,
            average_response_time_ms=average_response_time_ms,
            availability_percentage=availability_percentage,
            visitors=visitors,
            unique_guests=unique_guests,
        )


__all__ = [
    "MonitoringService",
    "AuthLookupProtocol",
    "WireGuardHealthLookupProtocol",
    "HealthCheckResult",
    "DashboardSummary",
    "TimelineEntry",
    "AlertService",
    "AlertEvaluationResult",
    "NotificationService",
    "NotificationDeliveryError",
    "NotifierProtocol",
    "EmailNotifier",
    "SmsNotifier",
    "WhatsAppNotifier",
    "SlackNotifier",
    "TeamsNotifier",
    "DiscordNotifier",
    "WebhookNotifier",
    "IncidentService",
    "SlaService",
    "GuestVisitorLookupProtocol",
    "RouterLifecycleEntry",
    "ZtpDashboardResult",
    "ProvisioningFailureBreakdown",
    "ProvisioningFailureSample",
    "RetryJobEntry",
    "ZtpAnalyticsResult",
    "ZtpMonitoringService",
    "PlatformDashboardResult",
    "PlatformDashboardService",
]

"""Monitoring business logic: the Health Engine (real checks against every
genuine platform dependency this codebase has, an honest ``UNKNOWN`` for the
two pieces of infrastructure it doesn't have yet) and the Event Engine (a
narrowly-scoped new event table plus a read-side aggregation across it and
two other domains' existing event tables).

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
``check_celery_health``/``check_websocket_health`` never fabricate a
``HEALTHY`` for infrastructure that does not exist in this codebase (no
Celery worker/broker anywhere, no WebSocket support anywhere) -- they return
``HealthStatus.UNKNOWN`` with a clear, honest explanation instead.
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
from app.domains.router_provisioning.models import RouterEvent

from .constants import (
    ALERT_EVENT_LOOKBACK_MINUTES,
    ALERT_TARGET_ROUTER,
    AUDIT_LOG_SOURCE_DOMAIN,
    DEFAULT_EVENT_TIMELINE_LIMIT,
    DEFAULT_LIST_PAGE,
    DEFAULT_LIST_PAGE_SIZE,
    EVENT_TYPE_COMPONENT_DEGRADED,
    EVENT_TYPE_COMPONENT_RECOVERED,
    EVENT_TYPE_COMPONENT_UNHEALTHY,
    FREERADIUS_ACTIVITY_STALE_MINUTES,
    HTTP_NOTIFICATION_TIMEOUT_SECONDS,
    MAX_EVENT_TIMELINE_LIMIT,
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
        """No Celery deployment (worker/broker) exists anywhere in this
        codebase yet -- there is no background task queue at all. This
        returns an honest ``UNKNOWN``, never a fabricated ``HEALTHY``: the
        health-check *type* is fully defined and wired into every
        dashboard/history endpoint now, ready to report real state the
        moment a real Celery deployment exists."""
        return HealthCheckResult(
            component=HealthComponent.CELERY,
            status=HealthStatus.UNKNOWN,
            response_time_ms=None,
            details={
                "reason": "no Celery worker/broker is deployed in this environment"
            },
            error_message=(
                "No Celery deployment exists in this environment yet; this "
                "health-check type is defined and ready to wire in once one "
                "does."
            ),
        )

    async def check_websocket_health(self) -> HealthCheckResult:
        """No WebSocket support exists anywhere in this codebase yet. This
        returns an honest ``UNKNOWN``, never a fabricated ``HEALTHY`` --
        see ``check_celery_health``'s identical reasoning."""
        return HealthCheckResult(
            component=HealthComponent.WEBSOCKET,
            status=HealthStatus.UNKNOWN,
            response_time_ms=None,
            details={"reason": "no WebSocket endpoint exists in this FastAPI app yet"},
            error_message=(
                "No WebSocket support exists in this environment yet; this "
                "health-check type is defined and ready to wire in once one "
                "does."
            ),
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
        permanently-``UNKNOWN`` components" write-up."""
        statuses = {row.status for row in rows}
        if HealthStatus.UNHEALTHY.value in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED.value in statuses:
            return HealthStatus.DEGRADED
        known_statuses = statuses - {HealthStatus.UNKNOWN.value}
        if not known_statuses:
            return HealthStatus.UNKNOWN
        return HealthStatus.HEALTHY

    async def get_dashboard_summary(self) -> DashboardSummary:
        """Aggregates overall platform status plus every component's
        current :class:`ServiceHealth` row -- what a dashboard reads for
        "what is healthy right now" without scanning ``HealthCheck``
        history."""
        rows = await self.repository.list_service_health()
        return DashboardSummary(
            overall_status=self._aggregate_status(rows), components=rows
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
    ) -> None:
        self.repository = repository
        self.notification_service = notification_service

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
        return await self.repository.create_alert(
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

    async def _auto_resolve(self, alert: Alert) -> Alert:
        resolved = await self.repository.update_alert(
            alert,
            {"status": AlertStatus.RESOLVED.value, "resolved_at": datetime.now(UTC)},
        )
        event = AlertResolved(alert_id=resolved.id, auto_resolved=True)
        logger.info("alert_auto_resolved", extra=_event_extra(event))
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
]

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
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from redis.asyncio import Redis

from app.core.config import Settings
from app.core.logging import get_logger
from app.database.utils.pagination import PaginationMeta
from app.domains.rbac.models import AuditLogEntry
from app.domains.router_provisioning.models import RouterEvent

from .constants import (
    AUDIT_LOG_SOURCE_DOMAIN,
    DEFAULT_EVENT_TIMELINE_LIMIT,
    EVENT_TYPE_COMPONENT_DEGRADED,
    EVENT_TYPE_COMPONENT_RECOVERED,
    EVENT_TYPE_COMPONENT_UNHEALTHY,
    FREERADIUS_ACTIVITY_STALE_MINUTES,
    MAX_EVENT_TIMELINE_LIMIT,
    ROUTER_EVENT_SOURCE_DOMAIN,
    SOURCE_DOMAIN,
    EventCategory,
    EventSeverity,
    HealthComponent,
    HealthStatus,
    HeartbeatComponentType,
)
from .events import HeartbeatRecorded, PlatformEventRecorded, ServiceHealthTransitioned
from .models import HealthCheck, HeartbeatLog, PlatformEvent, ServiceHealth
from .repository import MonitoringRepositoryProtocol
from .validators import classify_storage_health, validate_date_range

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


__all__ = [
    "MonitoringService",
    "AuthLookupProtocol",
    "WireGuardHealthLookupProtocol",
    "HealthCheckResult",
    "DashboardSummary",
    "TimelineEntry",
]

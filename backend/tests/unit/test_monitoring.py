"""Unit tests for the Monitoring domain (BE-011 Part 1: Health Engine +
Event Engine): each real health check's success and simulated-failure
paths, the Celery/WebSocket honest-``UNKNOWN``-not-fabricated behavior, the
FreeRADIUS/WireGuard proxy-signal checks, ``ServiceHealth`` rollup +
consecutive-failure tracking, dashboard aggregate-status logic, the event
timeline's cross-source aggregation/sorting/filtering, and heartbeat
recording.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_guest.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``MonitoringService`` is exercised against a small, hand-rolled
in-memory fake repository and fakes for every composed cross-domain
dependency (auth repository, Redis client, WireGuard service) -- there is
no live Postgres/Redis in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.domains.monitoring.constants import (
    EVENT_TYPE_COMPONENT_DEGRADED,
    EVENT_TYPE_COMPONENT_RECOVERED,
    EVENT_TYPE_COMPONENT_UNHEALTHY,
    STORAGE_DEGRADED_USED_PERCENT,
    STORAGE_UNHEALTHY_USED_PERCENT,
    EventCategory,
    EventSeverity,
    HealthComponent,
    HealthStatus,
    HeartbeatComponentType,
)
from app.domains.monitoring.exceptions import InvalidEventDateRangeError
from app.domains.monitoring.models import (
    HealthCheck,
    HeartbeatLog,
    PlatformEvent,
    ServiceHealth,
)
from app.domains.monitoring.service import MonitoringService
from app.domains.monitoring.validators import (
    classify_storage_health,
    validate_date_range,
)
from app.domains.rbac.models import AuditLogEntry
from app.domains.router_provisioning.models import RouterEvent
from app.domains.wireguard.models import WireGuardPeer

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeMonitoringRepository:
    """Stand-in for ``MonitoringRepositoryProtocol``."""

    ping_should_raise: Exception | None = None
    health_checks: list[dict[str, object]] = field(default_factory=list)
    service_health_rows: dict[str, ServiceHealth] = field(default_factory=dict)
    heartbeat_logs: list[dict[str, object]] = field(default_factory=list)
    platform_events: list[PlatformEvent] = field(default_factory=list)
    audit_entries: list[AuditLogEntry] = field(default_factory=list)
    router_events: list[RouterEvent] = field(default_factory=list)
    active_nas_count: int = 0
    latest_guest_activity: datetime | None = None
    wireguard_peers: list[WireGuardPeer] = field(default_factory=list)

    async def ping_database(self) -> None:
        if self.ping_should_raise is not None:
            raise self.ping_should_raise

    async def create_health_check(self, **fields: object) -> HealthCheck:
        self.health_checks.append(fields)
        return HealthCheck(**_base_fields(**fields))

    async def list_health_checks(self, *, component: str, page: int, page_size: int):
        raise NotImplementedError("not exercised by these unit tests")

    async def get_service_health(self, component: str) -> ServiceHealth | None:
        return self.service_health_rows.get(component)

    async def create_service_health(self, **fields: object) -> ServiceHealth:
        row = ServiceHealth(**_base_fields(**fields))
        self.service_health_rows[row.component] = row
        return row

    async def update_service_health(
        self, service_health: ServiceHealth, data: dict[str, object]
    ) -> ServiceHealth:
        for key, value in data.items():
            setattr(service_health, key, value)
        self.service_health_rows[service_health.component] = service_health
        return service_health

    async def list_service_health(self) -> list[ServiceHealth]:
        return list(self.service_health_rows.values())

    async def create_heartbeat_log(self, **fields: object) -> HeartbeatLog:
        self.heartbeat_logs.append(fields)
        return HeartbeatLog(**_base_fields(**fields))

    async def create_platform_event(self, **fields: object) -> PlatformEvent:
        event = PlatformEvent(**_base_fields(**fields))
        self.platform_events.append(event)
        return event

    async def list_platform_events(
        self,
        *,
        organization_id=None,
        categories=None,
        severities=None,
        start=None,
        end=None,
        limit=100,
    ) -> list[PlatformEvent]:
        results = list(self.platform_events)
        if organization_id is not None:
            results = [e for e in results if e.organization_id == organization_id]
        if categories:
            results = [e for e in results if e.category in categories]
        if severities:
            results = [e for e in results if e.severity in severities]
        if start is not None:
            results = [e for e in results if e.occurred_at >= start]
        if end is not None:
            results = [e for e in results if e.occurred_at <= end]
        return results[:limit]

    async def list_audit_log_events(
        self, *, organization_id=None, start=None, end=None, limit=100
    ) -> list[AuditLogEntry]:
        results = list(self.audit_entries)
        if organization_id is not None:
            results = [e for e in results if e.organization_id == organization_id]
        if start is not None:
            results = [e for e in results if e.created_at >= start]
        if end is not None:
            results = [e for e in results if e.created_at <= end]
        return results[:limit]

    async def list_router_events(
        self, *, organization_id=None, start=None, end=None, limit=100
    ) -> list[RouterEvent]:
        results = list(self.router_events)
        if start is not None:
            results = [e for e in results if e.occurred_at >= start]
        if end is not None:
            results = [e for e in results if e.occurred_at <= end]
        return results[:limit]

    async def count_active_radius_nas_clients(self) -> int:
        return self.active_nas_count

    async def get_latest_guest_accounting_activity(self) -> datetime | None:
        return self.latest_guest_activity

    async def list_wireguard_peers(self) -> list[WireGuardPeer]:
        return list(self.wireguard_peers)


@dataclass
class FakeRedisClient:
    should_raise: Exception | None = None

    async def ping(self) -> bool:
        if self.should_raise is not None:
            raise self.should_raise
        return True


@dataclass
class FakeAuthRepository:
    should_raise: Exception | None = None

    async def list_users(self, *, page: int, page_size: int):
        if self.should_raise is not None:
            raise self.should_raise
        return [], None


@dataclass
class FakeWireGuardService:
    """Stand-in for ``WireGuardHealthLookupProtocol`` -- returns a
    preconfigured status per peer id rather than reimplementing
    ``WireGuardService.compute_health_status``'s own staleness threshold
    (this module composes with, never reimplements, that method)."""

    statuses_by_peer_id: dict[uuid.UUID, HealthStatus] = field(default_factory=dict)

    def compute_health_status(self, peer, *, now=None):
        return self.statuses_by_peer_id[peer.id]


def _settings(*, log_dir) -> Settings:
    return Settings(log_dir=log_dir)


_UNSET = object()


def _make_service(
    *,
    repository: FakeMonitoringRepository | None = None,
    redis_client: FakeRedisClient | None = None,
    settings: Settings | None = None,
    auth_repository: object = _UNSET,
    wireguard_service: FakeWireGuardService | None = None,
) -> tuple[MonitoringService, FakeMonitoringRepository]:
    repo = repository or FakeMonitoringRepository()
    resolved_auth_repository = (
        FakeAuthRepository() if auth_repository is _UNSET else auth_repository
    )
    service = MonitoringService(
        repo,
        redis_client or FakeRedisClient(),
        settings or Settings(),
        auth_repository=resolved_auth_repository,
        wireguard_service=wireguard_service,
    )
    return service, repo


def _wireguard_peer(*, status: str = "active", last_handshake_at=None) -> WireGuardPeer:
    return WireGuardPeer(
        **_base_fields(
            router_id=uuid.uuid4(),
            server_id=uuid.uuid4(),
            tunnel_ip_address="10.100.0.2",
            public_key=uuid.uuid4().hex,
            private_key_encrypted="ciphertext",
            status=status,
            rotation_count=0,
            last_handshake_at=last_handshake_at,
            revoked_at=None,
        )
    )


def _audit_log_entry(*, created_at, organization_id=None) -> AuditLogEntry:
    return AuditLogEntry(
        **_base_fields(
            actor_user_id=uuid.uuid4(),
            action="router_created",
            entity_type="router",
            entity_id=uuid.uuid4(),
            description="Router created",
            event_metadata={},
            organization_id=organization_id,
            location_id=None,
            created_at=created_at,
        )
    )


def _router_event(
    *, occurred_at, event_type="config_applied", router_id=None
) -> RouterEvent:
    return RouterEvent(
        **_base_fields(
            router_id=router_id or uuid.uuid4(),
            event_type=event_type,
            message=f"{event_type} event",
            occurred_at=occurred_at,
            event_metadata={},
        )
    )


# ============================================================================
# Database health
# ============================================================================


async def test_check_database_health_success():
    service, _ = _make_service()
    result = await service.check_database_health()
    assert result.status == HealthStatus.HEALTHY
    assert result.error_message is None
    assert isinstance(result.response_time_ms, float)


async def test_check_database_health_failure():
    repo = FakeMonitoringRepository(
        ping_should_raise=RuntimeError("connection refused")
    )
    service, _ = _make_service(repository=repo)
    result = await service.check_database_health()
    assert result.status == HealthStatus.UNHEALTHY
    assert result.error_message == "connection refused"


# ============================================================================
# Redis health
# ============================================================================


async def test_check_redis_health_success():
    service, _ = _make_service()
    result = await service.check_redis_health()
    assert result.status == HealthStatus.HEALTHY
    assert result.error_message is None


async def test_check_redis_health_failure():
    service, _ = _make_service(
        redis_client=FakeRedisClient(should_raise=TimeoutError())
    )
    result = await service.check_redis_health()
    assert result.status == HealthStatus.UNHEALTHY
    assert result.error_message is not None


# ============================================================================
# API health (trivial)
# ============================================================================


async def test_check_api_health_is_always_healthy():
    service, _ = _make_service()
    result = await service.check_api_health()
    assert result.status == HealthStatus.HEALTHY
    assert result.component == HealthComponent.API


# ============================================================================
# Auth health
# ============================================================================


async def test_check_auth_health_success():
    service, _ = _make_service(auth_repository=FakeAuthRepository())
    result = await service.check_auth_health()
    assert result.status == HealthStatus.HEALTHY
    assert result.error_message is None


async def test_check_auth_health_failure():
    service, _ = _make_service(
        auth_repository=FakeAuthRepository(should_raise=RuntimeError("db down"))
    )
    result = await service.check_auth_health()
    assert result.status == HealthStatus.UNHEALTHY
    assert result.error_message == "db down"


async def test_check_auth_health_not_wired():
    service, _ = _make_service(auth_repository=None)
    result = await service.check_auth_health()
    assert result.status == HealthStatus.UNHEALTHY


# ============================================================================
# Storage health -- pure classification tests (deterministic, no disk I/O
# flakiness) plus one integration-style smoke test.
# ============================================================================


def test_classify_storage_health_not_writable_is_unhealthy():
    assert (
        classify_storage_health(percent_used=1.0, writable=False)
        == HealthStatus.UNHEALTHY
    )


def test_classify_storage_health_below_thresholds_is_healthy():
    assert (
        classify_storage_health(percent_used=10.0, writable=True)
        == HealthStatus.HEALTHY
    )


def test_classify_storage_health_degraded_threshold():
    assert (
        classify_storage_health(
            percent_used=STORAGE_DEGRADED_USED_PERCENT + 1, writable=True
        )
        == HealthStatus.DEGRADED
    )


def test_classify_storage_health_unhealthy_threshold():
    assert (
        classify_storage_health(
            percent_used=STORAGE_UNHEALTHY_USED_PERCENT + 1, writable=True
        )
        == HealthStatus.UNHEALTHY
    )


async def test_check_storage_health_smoke(tmp_path):
    service, _ = _make_service(settings=_settings(log_dir=tmp_path))
    result = await service.check_storage_health()
    assert result.component == HealthComponent.STORAGE
    assert result.details is not None
    assert result.details["writable"] is True
    assert result.status in (
        HealthStatus.HEALTHY,
        HealthStatus.DEGRADED,
        HealthStatus.UNHEALTHY,
    )


# ============================================================================
# Celery / WebSocket -- honest UNKNOWN, never fabricated HEALTHY
# ============================================================================


async def test_check_celery_health_is_unknown_not_healthy():
    service, _ = _make_service()
    result = await service.check_celery_health()
    assert result.status == HealthStatus.UNKNOWN
    assert result.status != HealthStatus.HEALTHY
    assert "No Celery deployment exists" in (result.error_message or "")


async def test_check_websocket_health_is_unknown_not_healthy():
    service, _ = _make_service()
    result = await service.check_websocket_health()
    assert result.status == HealthStatus.UNKNOWN
    assert result.status != HealthStatus.HEALTHY
    assert "No WebSocket support exists" in (result.error_message or "")


# ============================================================================
# FreeRADIUS proxy signal
# ============================================================================


async def test_check_freeradius_health_no_nas_clients_is_unknown():
    repo = FakeMonitoringRepository(active_nas_count=0)
    service, _ = _make_service(repository=repo)
    result = await service.check_freeradius_health()
    assert result.status == HealthStatus.UNKNOWN


async def test_check_freeradius_health_recent_activity_is_healthy():
    repo = FakeMonitoringRepository(active_nas_count=2, latest_guest_activity=_now())
    service, _ = _make_service(repository=repo)
    result = await service.check_freeradius_health()
    assert result.status == HealthStatus.HEALTHY


async def test_check_freeradius_health_stale_activity_is_degraded():
    repo = FakeMonitoringRepository(
        active_nas_count=2, latest_guest_activity=_now() - timedelta(hours=5)
    )
    service, _ = _make_service(repository=repo)
    result = await service.check_freeradius_health()
    assert result.status == HealthStatus.DEGRADED


async def test_check_freeradius_health_never_any_activity_is_degraded():
    repo = FakeMonitoringRepository(active_nas_count=1, latest_guest_activity=None)
    service, _ = _make_service(repository=repo)
    result = await service.check_freeradius_health()
    assert result.status == HealthStatus.DEGRADED


# ============================================================================
# WireGuard proxy signal
# ============================================================================


async def test_check_wireguard_health_no_peers_is_unknown():
    service, _ = _make_service(wireguard_service=FakeWireGuardService())
    result = await service.check_wireguard_health()
    assert result.status == HealthStatus.UNKNOWN


async def test_check_wireguard_health_not_wired_is_unknown():
    service, _ = _make_service(wireguard_service=None)
    result = await service.check_wireguard_health()
    assert result.status == HealthStatus.UNKNOWN


async def test_check_wireguard_health_all_healthy():
    peer = _wireguard_peer()
    repo = FakeMonitoringRepository(wireguard_peers=[peer])
    wg = FakeWireGuardService(statuses_by_peer_id={peer.id: HealthStatus.HEALTHY})
    service, _ = _make_service(repository=repo, wireguard_service=wg)
    result = await service.check_wireguard_health()
    assert result.status == HealthStatus.HEALTHY


async def test_check_wireguard_health_some_stale_is_degraded():
    healthy_peer = _wireguard_peer()
    stale_peer = _wireguard_peer()
    repo = FakeMonitoringRepository(wireguard_peers=[healthy_peer, stale_peer])
    wg = FakeWireGuardService(
        statuses_by_peer_id={
            healthy_peer.id: HealthStatus.HEALTHY,
            stale_peer.id: "stale",
        }
    )
    service, _ = _make_service(repository=repo, wireguard_service=wg)
    result = await service.check_wireguard_health()
    assert result.status == HealthStatus.DEGRADED


async def test_check_wireguard_health_all_stale_is_unhealthy():
    peer = _wireguard_peer()
    repo = FakeMonitoringRepository(wireguard_peers=[peer])
    wg = FakeWireGuardService(statuses_by_peer_id={peer.id: "stale"})
    service, _ = _make_service(repository=repo, wireguard_service=wg)
    result = await service.check_wireguard_health()
    assert result.status == HealthStatus.UNHEALTHY


async def test_check_wireguard_health_excludes_revoked_peers():
    revoked_peer = _wireguard_peer(status="revoked")
    repo = FakeMonitoringRepository(wireguard_peers=[revoked_peer])
    wg = FakeWireGuardService()
    service, _ = _make_service(repository=repo, wireguard_service=wg)
    result = await service.check_wireguard_health()
    # Only revoked peers exist -> treated as "no active peers".
    assert result.status == HealthStatus.UNKNOWN


# ============================================================================
# ServiceHealth rollup + consecutive-failure tracking
# ============================================================================


async def test_run_all_health_checks_persists_every_component():
    repo = FakeMonitoringRepository(active_nas_count=0)
    service, _ = _make_service(repository=repo)
    results = await service.run_all_health_checks()
    components = {r.component for r in results}
    assert components == set(HealthComponent)
    assert len(repo.health_checks) == len(HealthComponent)
    assert len(repo.service_health_rows) == len(HealthComponent)


async def test_consecutive_failure_count_increments_and_resets():
    repo = FakeMonitoringRepository(ping_should_raise=RuntimeError("boom"))
    service, _ = _make_service(repository=repo)

    await service.run_all_health_checks()
    row = repo.service_health_rows[HealthComponent.DATABASE.value]
    assert row.status == HealthStatus.UNHEALTHY.value
    assert row.consecutive_failure_count == 1

    await service.run_all_health_checks()
    row = repo.service_health_rows[HealthComponent.DATABASE.value]
    assert row.consecutive_failure_count == 2

    # Recovery resets the counter to zero.
    repo.ping_should_raise = None
    await service.run_all_health_checks()
    row = repo.service_health_rows[HealthComponent.DATABASE.value]
    assert row.status == HealthStatus.HEALTHY.value
    assert row.consecutive_failure_count == 0


async def test_status_transition_writes_platform_event():
    repo = FakeMonitoringRepository(ping_should_raise=RuntimeError("boom"))
    service, _ = _make_service(repository=repo)

    await service.run_all_health_checks()
    unhealthy_events = [
        e
        for e in repo.platform_events
        if e.event_type == EVENT_TYPE_COMPONENT_UNHEALTHY
    ]
    assert len(unhealthy_events) == 1
    assert unhealthy_events[0].category == EventCategory.SYSTEM.value
    assert unhealthy_events[0].severity == EventSeverity.CRITICAL.value

    # Same failure again -> no new transition event (status didn't change).
    await service.run_all_health_checks()
    unhealthy_events = [
        e
        for e in repo.platform_events
        if e.event_type == EVENT_TYPE_COMPONENT_UNHEALTHY
    ]
    assert len(unhealthy_events) == 1

    # Recovery -> a "recovered" transition event.
    repo.ping_should_raise = None
    await service.run_all_health_checks()
    recovered_events = [
        e
        for e in repo.platform_events
        if e.event_type == EVENT_TYPE_COMPONENT_RECOVERED
    ]
    assert len(recovered_events) == 1


async def test_degraded_transition_writes_warning_event():
    repo = FakeMonitoringRepository(active_nas_count=2, latest_guest_activity=None)
    service, _ = _make_service(repository=repo)
    await service.run_all_health_checks()
    degraded_events = [
        e for e in repo.platform_events if e.event_type == EVENT_TYPE_COMPONENT_DEGRADED
    ]
    assert len(degraded_events) == 1
    assert degraded_events[0].severity == EventSeverity.WARNING.value


# ============================================================================
# Dashboard aggregate-status logic
# ============================================================================


async def test_dashboard_summary_never_run_is_unknown():
    service, _ = _make_service()
    summary = await service.get_dashboard_summary()
    assert summary.overall_status == HealthStatus.UNKNOWN
    assert summary.components == []


async def test_dashboard_summary_all_healthy_excludes_permanently_unknown():
    """Celery/WebSocket are honestly UNKNOWN forever in this environment --
    the aggregate must still be able to report HEALTHY when every *other*
    component is healthy (see service.py's module docstring)."""
    repo = FakeMonitoringRepository(active_nas_count=0)
    service, _ = _make_service(repository=repo)
    await service.run_all_health_checks()
    summary = await service.get_dashboard_summary()
    assert summary.overall_status == HealthStatus.HEALTHY


async def test_dashboard_summary_one_degraded():
    repo = FakeMonitoringRepository(active_nas_count=2, latest_guest_activity=None)
    service, _ = _make_service(repository=repo)
    await service.run_all_health_checks()
    summary = await service.get_dashboard_summary()
    assert summary.overall_status == HealthStatus.DEGRADED


async def test_dashboard_summary_one_unhealthy():
    repo = FakeMonitoringRepository(ping_should_raise=RuntimeError("boom"))
    service, _ = _make_service(repository=repo)
    await service.run_all_health_checks()
    summary = await service.get_dashboard_summary()
    assert summary.overall_status == HealthStatus.UNHEALTHY


async def test_dashboard_summary_unhealthy_takes_priority_over_degraded():
    repo = FakeMonitoringRepository(
        ping_should_raise=RuntimeError("boom"),
        active_nas_count=2,
        latest_guest_activity=None,
    )
    service, _ = _make_service(repository=repo)
    await service.run_all_health_checks()
    summary = await service.get_dashboard_summary()
    assert summary.overall_status == HealthStatus.UNHEALTHY


# ============================================================================
# Heartbeats
# ============================================================================


async def test_record_heartbeat_creates_row():
    service, repo = _make_service()
    router_id = uuid.uuid4()
    heartbeat = await service.record_heartbeat(
        component_type=HeartbeatComponentType.ROUTER,
        component_id=router_id,
        payload={"routeros_version": "7.15"},
    )
    assert heartbeat.component_type == HeartbeatComponentType.ROUTER.value
    assert heartbeat.component_id == router_id
    assert repo.heartbeat_logs[0]["payload"] == {"routeros_version": "7.15"}


# ============================================================================
# Event Engine: unified timeline aggregation
# ============================================================================


async def test_get_event_timeline_aggregates_all_three_sources():
    repo = FakeMonitoringRepository()
    now = _now()
    org_id = uuid.uuid4()

    service, _ = _make_service(repository=repo)
    await service.record_platform_event(
        category=EventCategory.SYSTEM,
        event_type="monitoring.component_unhealthy",
        severity=EventSeverity.CRITICAL,
        message="database unhealthy",
    )
    repo.audit_entries.append(
        _audit_log_entry(created_at=now - timedelta(minutes=5), organization_id=org_id)
    )
    repo.router_events.append(
        _router_event(
            occurred_at=now - timedelta(minutes=10), event_type="config_applied"
        )
    )

    entries = await service.get_event_timeline()
    assert len(entries) == 3
    sources = {e.source_domain for e in entries}
    assert sources == {"monitoring", "rbac", "router_provisioning"}


async def test_get_event_timeline_sorts_chronologically_descending():
    repo = FakeMonitoringRepository()
    now = _now()
    repo.router_events.append(
        _router_event(occurred_at=now - timedelta(hours=2), event_type="reboot")
    )
    repo.router_events.append(
        _router_event(occurred_at=now - timedelta(minutes=1), event_type="reboot")
    )
    service, _ = _make_service(repository=repo)

    entries = await service.get_event_timeline()
    assert entries == sorted(entries, key=lambda e: e.occurred_at, reverse=True)


async def test_get_event_timeline_filters_by_category():
    repo = FakeMonitoringRepository()
    now = _now()
    repo.audit_entries.append(_audit_log_entry(created_at=now))
    repo.router_events.append(_router_event(occurred_at=now))
    service, _ = _make_service(repository=repo)

    entries = await service.get_event_timeline(categories=[EventCategory.AUDIT])
    assert len(entries) == 1
    assert entries[0].category == EventCategory.AUDIT.value


async def test_get_event_timeline_router_event_failure_maps_to_warning():
    repo = FakeMonitoringRepository()
    repo.router_events.append(
        _router_event(occurred_at=_now(), event_type="config_failed")
    )
    service, _ = _make_service(repository=repo)

    entries = await service.get_event_timeline()
    assert entries[0].severity == EventSeverity.WARNING.value


async def test_get_event_timeline_invalid_date_range_raises():
    service, _ = _make_service()
    with pytest.raises(InvalidEventDateRangeError):
        await service.get_event_timeline(start=_now(), end=_now() - timedelta(days=1))


def test_validate_date_range_allows_open_ended_bounds():
    validate_date_range(None, _now())
    validate_date_range(_now(), None)
    validate_date_range(None, None)


def test_validate_date_range_rejects_start_after_end():
    with pytest.raises(InvalidEventDateRangeError):
        validate_date_range(_now(), _now() - timedelta(seconds=1))

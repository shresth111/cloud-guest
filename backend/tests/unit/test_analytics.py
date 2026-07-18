"""Unit tests for the Analytics domain (BE-012 Part 1: Analytics Core
Infrastructure): aggregation correctness for all 3 snapshot types
(``ORG_DAILY_SUMMARY``/``LOCATION_DAILY_SUMMARY``/``PLATFORM_DAILY_SUMMARY``),
``AnalyticsService`` persistence + the batch pipeline's per-organization
failure isolation, the manual trigger's organization-existence guard, the
Celery task wrappers' async-bridge behavior, the new
``app.core.celery_app.ping_celery_workers`` health-check primitive's three
outcomes, tenant isolation on the snapshot read path, and RBAC
permission-key wiring for both HTTP endpoints.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_monitoring.py``); ``asyncio_mode = "auto"`` runs async
tests directly. Every fake below is a small, hand-rolled stand-in for the
narrow protocol it satisfies -- there is no live Postgres/Redis/Celery
worker/broker anywhere in this test suite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.analytics.aggregation import (
    compute_location_daily_summary,
    compute_org_daily_summary,
    compute_platform_daily_summary,
)
from app.domains.analytics.constants import AnalyticsGranularity, AnalyticsSnapshotType
from app.domains.analytics.exceptions import AnalyticsOrganizationNotFoundError
from app.domains.analytics.models import AnalyticsSnapshot
from app.domains.analytics.service import AnalyticsService
from app.domains.analytics.validators import day_bounds_utc, validate_date_range
from app.domains.router.enums import RouterStatus

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
class FakeGuestSummary:
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


@dataclass
class FakeGuestAnalyticsService:
    """Stand-in for ``aggregation.GuestAnalyticsLookupProtocol`` -- returns
    a preconfigured summary per ``(organization_id, location_id)`` pair
    rather than reimplementing
    ``app.domains.guest.service.GuestAnalyticsService``'s own real SQL
    aggregate queries (this module composes with, never reimplements, that
    service -- see ``aggregation.py``'s module docstring)."""

    summaries: dict[tuple[uuid.UUID, uuid.UUID | None], FakeGuestSummary]
    calls: list[tuple[uuid.UUID, uuid.UUID | None, datetime, datetime]] = field(
        default_factory=list
    )

    async def get_summary(
        self, *, organization_id, location_id, start, end
    ) -> FakeGuestSummary:
        self.calls.append((organization_id, location_id, start, end))
        return self.summaries[(organization_id, location_id)]


@dataclass
class FakeAnalyticsRepository:
    """Stand-in for ``AnalyticsRepositoryProtocol``."""

    active_guest_sessions_by_scope: dict[
        tuple[uuid.UUID | None, uuid.UUID | None], int
    ] = field(default_factory=dict)
    router_status_counts_by_scope: dict[
        tuple[uuid.UUID | None, uuid.UUID | None], list[tuple[str, int]]
    ] = field(default_factory=dict)
    active_organization_ids: list[uuid.UUID] = field(default_factory=list)
    active_location_ids_by_organization: dict[uuid.UUID, list[uuid.UUID]] = field(
        default_factory=dict
    )
    platform_guest_aggregate: tuple[int, int] = (0, 0)
    platform_organization_count: int = 0
    platform_location_count: int = 0
    existing_organization_ids: set[uuid.UUID] = field(default_factory=set)
    snapshots: list[AnalyticsSnapshot] = field(default_factory=list)
    # Simulates one organization's aggregation genuinely failing (e.g. a bad
    # row) -- create_snapshot raises when persisting this organization's own
    # ORG_DAILY_SUMMARY row.
    fail_organization_id: uuid.UUID | None = None

    async def create_snapshot(self, **fields: object) -> AnalyticsSnapshot:
        is_org_summary = (
            fields.get("snapshot_type") == AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value
        )
        if (
            self.fail_organization_id is not None
            and fields.get("organization_id") == self.fail_organization_id
            and is_org_summary
        ):
            raise RuntimeError("simulated aggregation failure for this organization")
        snapshot = AnalyticsSnapshot(**_base_fields(**fields))
        self.snapshots.append(snapshot)
        return snapshot

    async def get_snapshot(self, snapshot_id):
        return next((s for s in self.snapshots if s.id == snapshot_id), None)

    async def get_latest_snapshot(self, *, organization_id, location_id, snapshot_type):
        matches = [
            s
            for s in self.snapshots
            if s.organization_id == organization_id
            and s.location_id == location_id
            and s.snapshot_type == snapshot_type
        ]
        return max(matches, key=lambda s: s.period_start) if matches else None

    async def list_snapshots(
        self,
        *,
        organization_id=None,
        location_id=None,
        snapshot_type=None,
        start=None,
        end=None,
        page=1,
        page_size=25,
    ):
        from app.database.utils.pagination import PageParams, PaginationMeta

        items = list(self.snapshots)
        if organization_id is not None:
            items = [s for s in items if s.organization_id == organization_id]
        if location_id is not None:
            items = [s for s in items if s.location_id == location_id]
        if snapshot_type is not None:
            items = [s for s in items if s.snapshot_type == snapshot_type]
        if start is not None:
            items = [s for s in items if s.period_start >= start]
        if end is not None:
            items = [s for s in items if s.period_end <= end]
        items.sort(key=lambda s: s.period_start, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)

    async def organization_exists(self, organization_id: uuid.UUID) -> bool:
        return organization_id in self.existing_organization_ids

    async def list_active_organization_ids(self) -> list[uuid.UUID]:
        return list(self.active_organization_ids)

    async def list_active_location_ids_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[uuid.UUID]:
        return list(self.active_location_ids_by_organization.get(organization_id, []))

    async def count_routers_by_status(
        self, *, organization_id=None, location_id=None
    ) -> list[tuple[str, int]]:
        return self.router_status_counts_by_scope.get(
            (organization_id, location_id), []
        )

    async def count_active_guest_sessions(
        self, *, organization_id=None, location_id=None
    ) -> int:
        return self.active_guest_sessions_by_scope.get(
            (organization_id, location_id), 0
        )

    async def get_platform_guest_aggregate(self, *, start, end) -> tuple[int, int]:
        return self.platform_guest_aggregate

    async def count_platform_organizations(self) -> int:
        return self.platform_organization_count

    async def count_platform_locations(self) -> int:
        return self.platform_location_count


def _period() -> tuple[datetime, datetime]:
    end = _now()
    start = end - timedelta(days=1)
    return start, end


# ============================================================================
# validators.day_bounds_utc
# ============================================================================


def test_day_bounds_utc_today_so_far_is_partial_and_open():
    start, end = day_bounds_utc()
    now = datetime.now(UTC)
    assert start == now.replace(hour=0, minute=0, second=0, microsecond=0)
    assert start <= end <= now + timedelta(seconds=1)


def test_day_bounds_utc_days_ago_one_is_full_closed_yesterday():
    start, end = day_bounds_utc(days_ago=1)
    now = datetime.now(UTC)
    today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    assert start == today_midnight - timedelta(days=1)
    assert end == today_midnight


def test_day_bounds_utc_explicit_target_date():
    start, end = day_bounds_utc(target_date_iso="2026-01-15")
    assert start == datetime(2026, 1, 15, tzinfo=UTC)
    assert end == datetime(2026, 1, 16, tzinfo=UTC)


def test_validate_date_range_rejects_start_after_end():
    from app.domains.analytics.exceptions import InvalidAnalyticsDateRangeError

    with pytest.raises(InvalidAnalyticsDateRangeError):
        validate_date_range(_now(), _now() - timedelta(days=1))


def test_validate_date_range_allows_open_ended():
    validate_date_range(None, None)
    validate_date_range(_now(), None)
    validate_date_range(None, _now())


# ============================================================================
# aggregation.py -- pure computation, real SQL-aggregate composition
# ============================================================================


async def test_compute_org_daily_summary_shape_and_values():
    organization_id = uuid.uuid4()
    start, end = _period()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (organization_id, None): FakeGuestSummary(
                visitors=42,
                unique_guests=30,
                returning_guests=12,
                average_session_duration_seconds=123.45,
                total_bandwidth_bytes=999_999,
            )
        }
    )
    repository = FakeAnalyticsRepository(
        active_guest_sessions_by_scope={(organization_id, None): 5},
        router_status_counts_by_scope={
            (organization_id, None): [
                (RouterStatus.ONLINE.value, 8),
                (RouterStatus.OFFLINE.value, 2),
            ]
        },
    )

    metrics = await compute_org_daily_summary(
        organization_id=organization_id,
        period_start=start,
        period_end=end,
        guest_analytics=guest_analytics,
        repository=repository,
    )

    assert metrics == {
        "guest_count_unique": 30,
        "guest_count_new": 18,
        "guest_count_returning": 12,
        "session_count_total": 42,
        "session_count_active": 5,
        "average_session_duration_seconds": 123.45,
        "total_bandwidth_bytes": 999_999,
        "router_count_online": 8,
        "router_count_offline": 2,
        "router_count_total": 10,
    }
    # Composition, not duplication: the real guest-analytics summary call
    # was made with this exact scope/window.
    assert guest_analytics.calls == [(organization_id, None, start, end)]


async def test_compute_org_daily_summary_new_guests_never_negative():
    """Defensive floor: returning_guests should never exceed unique_guests
    in real data, but the metric must never go negative even if it did."""
    organization_id = uuid.uuid4()
    start, end = _period()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (organization_id, None): FakeGuestSummary(
                visitors=5,
                unique_guests=2,
                returning_guests=5,
                average_session_duration_seconds=None,
                total_bandwidth_bytes=0,
            )
        }
    )
    repository = FakeAnalyticsRepository()

    metrics = await compute_org_daily_summary(
        organization_id=organization_id,
        period_start=start,
        period_end=end,
        guest_analytics=guest_analytics,
        repository=repository,
    )
    assert metrics["guest_count_new"] == 0


async def test_compute_location_daily_summary_scopes_guest_and_router_queries():
    organization_id = uuid.uuid4()
    location_id = uuid.uuid4()
    start, end = _period()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (organization_id, location_id): FakeGuestSummary(
                visitors=7,
                unique_guests=6,
                returning_guests=1,
                average_session_duration_seconds=50.0,
                total_bandwidth_bytes=1234,
            )
        }
    )
    repository = FakeAnalyticsRepository(
        active_guest_sessions_by_scope={(organization_id, location_id): 3},
        router_status_counts_by_scope={
            (organization_id, location_id): [(RouterStatus.ONLINE.value, 1)]
        },
    )

    metrics = await compute_location_daily_summary(
        organization_id=organization_id,
        location_id=location_id,
        period_start=start,
        period_end=end,
        guest_analytics=guest_analytics,
        repository=repository,
    )

    assert metrics["guest_count_unique"] == 6
    assert metrics["guest_count_new"] == 5
    assert metrics["session_count_active"] == 3
    assert metrics["router_count_online"] == 1
    assert metrics["router_count_offline"] == 0
    assert metrics["router_count_total"] == 1
    assert guest_analytics.calls == [(organization_id, location_id, start, end)]


async def test_compute_platform_daily_summary_is_platform_wide():
    start, end = _period()
    repository = FakeAnalyticsRepository(
        platform_organization_count=4,
        platform_location_count=9,
        platform_guest_aggregate=(100, 55),
        router_status_counts_by_scope={
            (None, None): [
                (RouterStatus.ONLINE.value, 20),
                (RouterStatus.OFFLINE.value, 3),
                (RouterStatus.SUSPENDED.value, 1),
            ]
        },
    )

    metrics = await compute_platform_daily_summary(
        period_start=start, period_end=end, repository=repository
    )

    assert metrics == {
        "organization_count_total": 4,
        "location_count_total": 9,
        "router_count_online": 20,
        "router_count_offline": 3,
        "router_count_total": 24,
        "guest_count_unique_today": 55,
        "session_count_total_today": 100,
    }


# ============================================================================
# AnalyticsService -- compute + persist
# ============================================================================


def _service_with(
    repository: FakeAnalyticsRepository, guest_analytics: FakeGuestAnalyticsService
) -> AnalyticsService:
    return AnalyticsService(repository, guest_analytics)


async def test_compute_and_store_org_daily_summary_persists_expected_row():
    organization_id = uuid.uuid4()
    start, end = _period()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (organization_id, None): FakeGuestSummary(
                visitors=1,
                unique_guests=1,
                returning_guests=0,
                average_session_duration_seconds=10.0,
                total_bandwidth_bytes=10,
            )
        }
    )
    repository = FakeAnalyticsRepository()
    service = _service_with(repository, guest_analytics)

    snapshot = await service.compute_and_store_org_daily_summary(
        organization_id=organization_id, period_start=start, period_end=end
    )

    assert snapshot.organization_id == organization_id
    assert snapshot.location_id is None
    assert snapshot.snapshot_type == AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value
    assert snapshot.granularity == AnalyticsGranularity.DAILY.value
    assert snapshot.metrics["guest_count_unique"] == 1
    assert snapshot.computation_duration_ms is not None
    assert snapshot.computation_duration_ms >= 0
    assert repository.snapshots == [snapshot]


async def test_run_daily_aggregation_for_organization_persists_org_and_locations():
    organization_id = uuid.uuid4()
    location_id_1 = uuid.uuid4()
    location_id_2 = uuid.uuid4()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (organization_id, None): FakeGuestSummary(1, 1, 0, None, 0),
            (organization_id, location_id_1): FakeGuestSummary(1, 1, 0, None, 0),
            (organization_id, location_id_2): FakeGuestSummary(1, 1, 0, None, 0),
        }
    )
    repository = FakeAnalyticsRepository(
        active_location_ids_by_organization={
            organization_id: [location_id_1, location_id_2]
        }
    )
    service = _service_with(repository, guest_analytics)

    snapshots = await service.run_daily_aggregation_for_organization(organization_id)

    assert len(snapshots) == 3
    assert snapshots[0].snapshot_type == AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value
    assert snapshots[0].location_id is None
    location_snapshots = snapshots[1:]
    assert {s.location_id for s in location_snapshots} == {
        location_id_1,
        location_id_2,
    }
    assert all(
        s.snapshot_type == AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value
        for s in location_snapshots
    )
    assert all(s.organization_id == organization_id for s in location_snapshots)


# ============================================================================
# Per-organization failure isolation (the batch pipeline)
# ============================================================================


async def test_run_daily_aggregation_for_all_organizations_isolates_one_failure():
    org_ok = uuid.uuid4()
    org_bad = uuid.uuid4()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (org_ok, None): FakeGuestSummary(1, 1, 0, None, 0),
            (org_bad, None): FakeGuestSummary(1, 1, 0, None, 0),
        }
    )
    repository = FakeAnalyticsRepository(
        active_organization_ids=[org_ok, org_bad],
        fail_organization_id=org_bad,
    )
    service = _service_with(repository, guest_analytics)

    result = await service.run_daily_aggregation_for_all_organizations()

    assert result.total_organizations == 2
    assert result.succeeded_organizations == 1
    assert len(result.failed_organizations) == 1
    failed_org_id, error_message = result.failed_organizations[0]
    assert failed_org_id == org_bad
    assert "simulated aggregation failure" in error_message

    # The good organization's snapshot was still persisted...
    org_ok_snapshots = [
        s
        for s in repository.snapshots
        if s.organization_id == org_ok
        and s.snapshot_type == AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value
    ]
    assert len(org_ok_snapshots) == 1
    # ...and the platform-wide snapshot is still computed even though one
    # organization failed (it is an independent, whole-table aggregate, not
    # a sum of the per-organization results).
    platform_snapshots = [
        s
        for s in repository.snapshots
        if s.snapshot_type == AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value
    ]
    assert len(platform_snapshots) == 1


async def test_run_daily_aggregation_for_all_organizations_all_succeed():
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={
            (org_a, None): FakeGuestSummary(1, 1, 0, None, 0),
            (org_b, None): FakeGuestSummary(2, 2, 1, None, 0),
        }
    )
    repository = FakeAnalyticsRepository(active_organization_ids=[org_a, org_b])
    service = _service_with(repository, guest_analytics)

    result = await service.run_daily_aggregation_for_all_organizations()

    assert result.total_organizations == 2
    assert result.succeeded_organizations == 2
    assert result.failed_organizations == []


# ============================================================================
# Manual trigger
# ============================================================================


async def test_trigger_aggregation_raises_for_unknown_organization():
    repository = FakeAnalyticsRepository(existing_organization_ids=set())
    guest_analytics = FakeGuestAnalyticsService(summaries={})
    service = _service_with(repository, guest_analytics)

    with pytest.raises(AnalyticsOrganizationNotFoundError):
        await service.trigger_aggregation(uuid.uuid4())


async def test_trigger_aggregation_succeeds_for_known_organization():
    organization_id = uuid.uuid4()
    guest_analytics = FakeGuestAnalyticsService(
        summaries={(organization_id, None): FakeGuestSummary(1, 1, 0, None, 0)}
    )
    repository = FakeAnalyticsRepository(
        existing_organization_ids={organization_id},
    )
    service = _service_with(repository, guest_analytics)

    snapshots = await service.trigger_aggregation(organization_id)

    assert len(snapshots) == 1
    assert snapshots[0].organization_id == organization_id


# ============================================================================
# Tenant isolation on the snapshot read path
# ============================================================================


async def test_list_snapshots_is_tenant_scoped():
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    guest_analytics = FakeGuestAnalyticsService(summaries={})
    repository = FakeAnalyticsRepository()
    service = _service_with(repository, guest_analytics)

    start, end = _period()
    await repository.create_snapshot(
        organization_id=org_a,
        location_id=None,
        snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
        period_start=start,
        period_end=end,
        granularity=AnalyticsGranularity.DAILY.value,
        metrics={},
        computed_at=_now(),
        computation_duration_ms=1.0,
    )
    await repository.create_snapshot(
        organization_id=org_b,
        location_id=None,
        snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
        period_start=start,
        period_end=end,
        granularity=AnalyticsGranularity.DAILY.value,
        metrics={},
        computed_at=_now(),
        computation_duration_ms=1.0,
    )

    items_a, meta_a = await service.list_snapshots(organization_id=org_a)
    assert len(items_a) == 1
    assert items_a[0].organization_id == org_a
    assert meta_a.total_items == 1

    items_b, meta_b = await service.list_snapshots(organization_id=org_b)
    assert len(items_b) == 1
    assert items_b[0].organization_id == org_b

    # No organization filter at all (a platform-wide/GLOBAL-scoped query)
    # sees both.
    items_all, meta_all = await service.list_snapshots()
    assert meta_all.total_items == 2


def test_list_snapshots_router_resolves_organization_id_via_current_organization():
    """Verifies tenant isolation is wired at the HTTP layer too: the
    ``organization_id`` query parameter on ``GET /analytics/snapshots`` is
    resolved through RBAC's own ``CurrentOrganization`` dependency (which
    validates the caller holds active membership in the named organization
    -- see ``app.domains.rbac.dependencies.CurrentOrganization``'s own
    docstring), never a raw, unchecked query parameter."""
    from app.domains.rbac.dependencies import CurrentOrganization
    from app.main import create_app

    app = create_app()
    route = next(
        r
        for r in app.routes
        if getattr(r, "path", None) == "/api/v1/analytics/snapshots"
        and "GET" in getattr(r, "methods", set())
    )

    # organization_id is a *parameter* dependency (Depends(CurrentOrganization)
    # in the endpoint signature), which FastAPI resolves as part of the main
    # dependant's own sub-dependants -- walk the full dependency tree.
    def _walk(dependant) -> set:
        calls = {d.call for d in dependant.dependencies}
        for d in dependant.dependencies:
            calls |= _walk(d)
        return calls

    all_calls = _walk(route.dependant)
    assert CurrentOrganization in all_calls


# ============================================================================
# RBAC permission-key wiring -- verified directly off the registered routes
# (mirrors tests/unit/test_monitoring_alerts.py's identical introspection
# pattern -- this codebase has no established route-level TestClient
# pattern, see that module's own docstring)
# ============================================================================


def _permission_key_for_route(route) -> str | None:
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            index = freevars.index("permission_key")
            return call.__closure__[index].cell_contents
    return None


@pytest.fixture(scope="module")
def analytics_routes_by_path_method():
    from app.main import create_app

    app = create_app()
    routes: dict[tuple[str, str], object] = {}
    for route in app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not methods or not path or not path.startswith("/api/v1/analytics"):
            continue
        for method in methods:
            routes[(path, method)] = route
    return routes


@pytest.mark.parametrize(
    ("path", "method", "expected_key"),
    [
        ("/api/v1/analytics/snapshots", "GET", "analytics.read"),
        ("/api/v1/analytics/snapshots/trigger", "POST", "reports.manage"),
    ],
)
def test_analytics_route_permission_keys(
    analytics_routes_by_path_method, path, method, expected_key
):
    route = analytics_routes_by_path_method[(path, method)]
    assert _permission_key_for_route(route) == expected_key


def test_app_boots_with_analytics_routes_registered_and_no_route_conflicts():
    from app.main import create_app

    app = create_app()
    analytics_paths = {
        getattr(r, "path", None)
        for r in app.routes
        if getattr(r, "path", None) and "analytics/snapshots" in r.path
    }
    assert "/api/v1/analytics/snapshots" in analytics_paths
    assert "/api/v1/analytics/snapshots/trigger" in analytics_paths

    seen: set[tuple[str, frozenset[str]]] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or methods is None:
            continue
        key = (path, frozenset(methods))
        assert key not in seen, f"duplicate route registered: {key}"
        seen.add(key)


# ============================================================================
# app.core.celery_app -- basic construction smoke test + the real
# ping_celery_workers health-check primitive's three outcomes
# ============================================================================


def test_celery_app_imports_and_constructs_without_a_broker():
    from app.core.celery_app import celery_app

    assert celery_app.main == "cloudguest"
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.accept_content == ["json"]
    assert celery_app.conf.result_serializer == "json"
    schedule_names = set(celery_app.conf.beat_schedule.keys())
    assert schedule_names == {"analytics-rolling-today", "analytics-finalize-yesterday"}


def test_ping_celery_workers_returns_pong_dict_when_worker_responds(monkeypatch):
    from app.core import celery_app as celery_app_module

    class _FakeInspect:
        def ping(self):
            return {"worker1@host": {"ok": "pong"}}

    monkeypatch.setattr(
        celery_app_module.celery_app.control,
        "inspect",
        lambda timeout=None: _FakeInspect(),
    )
    result = celery_app_module.ping_celery_workers()
    assert result == {"worker1@host": {"ok": "pong"}}


def test_ping_celery_workers_returns_none_when_no_worker_responds(monkeypatch):
    from app.core import celery_app as celery_app_module

    class _FakeInspect:
        def ping(self):
            return None

    monkeypatch.setattr(
        celery_app_module.celery_app.control,
        "inspect",
        lambda timeout=None: _FakeInspect(),
    )
    result = celery_app_module.ping_celery_workers()
    assert result is None


def test_ping_celery_workers_propagates_broker_unreachable_errors(monkeypatch):
    from app.core import celery_app as celery_app_module

    class _FakeInspect:
        def ping(self):
            raise ConnectionError("Connection refused")

    monkeypatch.setattr(
        celery_app_module.celery_app.control,
        "inspect",
        lambda timeout=None: _FakeInspect(),
    )
    with pytest.raises(ConnectionError):
        celery_app_module.ping_celery_workers()


# ============================================================================
# Celery task wrappers -- the async-bridge, mocked (no real worker/broker)
# ============================================================================


def test_run_daily_aggregation_for_all_organizations_task_bridges_into_async(
    monkeypatch,
):
    from app.domains.analytics import tasks as tasks_module
    from app.domains.analytics.service import AggregationBatchResult

    recorded: dict[str, object] = {}

    async def _fake_run_all_organizations_async(*, target_date_iso, days_ago):
        recorded["target_date_iso"] = target_date_iso
        recorded["days_ago"] = days_ago
        return AggregationBatchResult(
            total_organizations=2,
            succeeded_organizations=1,
            failed_organizations=[(uuid.uuid4(), "boom")],
        )

    monkeypatch.setattr(
        tasks_module, "_run_all_organizations_async", _fake_run_all_organizations_async
    )

    result = tasks_module.run_daily_aggregation_for_all_organizations(
        target_date_iso="2026-01-01", days_ago=0
    )

    assert recorded == {"target_date_iso": "2026-01-01", "days_ago": 0}
    assert result["total_organizations"] == 2
    assert result["succeeded_organizations"] == 1
    assert len(result["failed_organizations"]) == 1
    assert "organization_id" in result["failed_organizations"][0]


def test_run_daily_aggregation_for_organization_task_bridges_into_async(monkeypatch):
    from app.domains.analytics import tasks as tasks_module

    organization_id = uuid.uuid4()
    recorded: dict[str, object] = {}

    async def _fake_run_single_organization_async(org_id, *, target_date_iso, days_ago):
        recorded["organization_id"] = org_id
        recorded["target_date_iso"] = target_date_iso
        return 3

    monkeypatch.setattr(
        tasks_module,
        "_run_single_organization_async",
        _fake_run_single_organization_async,
    )

    result = tasks_module.run_daily_aggregation_for_organization(str(organization_id))

    assert recorded["organization_id"] == organization_id
    assert result == {
        "organization_id": str(organization_id),
        "snapshot_count": 3,
    }

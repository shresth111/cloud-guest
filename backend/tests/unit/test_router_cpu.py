"""``GET /analytics/venue-insights/router-cpu`` -- the customer dashboard's
Router CPU card.

1. Bucket-width selection (pure).
2. Service behaviour against an in-memory repository: series assembly,
   latest/stale, MikroTik-only roster, cross-tenant 404.
3. The SQL the real repository builds (compiled for PostgreSQL): tenant
   filters, vendor narrowing, bucket grouping.
4. Route contract: permission key + LOCATION scope, RequireOrganization,
   sibling-site 403, cross-tenant 404, envelope shape.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects import postgresql

from app.common.exceptions import register_exception_handlers
from app.domains.analytics.router_cpu import (
    MAX_POINTS,
    STALE_AFTER_SECONDS,
    CpuBucketRow,
    LatestReadingRow,
    MikrotikRouterRow,
    RouterCpuRepository,
    RouterCpuService,
    bucket_seconds_for,
)
from app.domains.analytics.venue_insights import LocationContext
from app.domains.analytics.venue_insights_router import (
    get_router_cpu_service,
)
from app.domains.analytics.venue_insights_router import (
    router as venue_router,
)
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentOrganization,
    RequireOrganization,
)
from app.domains.rbac.enums import ScopeType

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
LOC_A = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_B = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
R1 = uuid.UUID("00000000-0000-0000-0000-000000000101")
R2 = uuid.UUID("00000000-0000-0000-0000-000000000202")

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)


# ============================================================================
# 1. Bucket width
# ============================================================================


@pytest.mark.parametrize(
    ("span", "width"),
    [
        (timedelta(hours=1), 300),
        (timedelta(hours=24), 1800),
        (timedelta(days=7), 10800),
        (timedelta(days=30), 43200),
        (timedelta(days=92), 86400),
    ],
)
def test_bucket_width_keeps_points_bounded(span, width) -> None:
    assert bucket_seconds_for(NOW - span, NOW) == width
    if span <= timedelta(days=60):
        assert span.total_seconds() / width <= MAX_POINTS


# ============================================================================
# 2. Service
# ============================================================================


class _Repo:
    def __init__(self) -> None:
        self.locations: dict[uuid.UUID, uuid.UUID] = {}
        self.routers: dict[uuid.UUID, list[MikrotikRouterRow]] = {}
        self.buckets: list[CpuBucketRow] = []
        self.latest: dict[uuid.UUID, LatestReadingRow] = {}
        self.calls: list[str] = []

    async def get_location_context(self, *, organization_id, location_id):
        self.calls.append("context")
        if self.locations.get(location_id) != organization_id:
            return None
        return LocationContext(location_id=location_id, timezone="Asia/Kolkata")

    async def list_mikrotik_routers(self, *, organization_id, location_id):
        self.calls.append("routers")
        return list(self.routers.get(location_id, []))

    async def get_cpu_buckets(self, *, router_ids, start, end, bucket_seconds):
        self.calls.append("buckets")
        self.bucket_seconds = bucket_seconds
        return [b for b in self.buckets if b.router_id in router_ids]

    async def get_latest_readings(self, *, router_ids, since, until):
        self.calls.append("latest")
        return {k: v for k, v in self.latest.items() if k in router_ids}


def _repo_with_venue() -> _Repo:
    repo = _Repo()
    repo.locations[LOC_A] = ORG_A
    repo.locations[LOC_B] = ORG_B
    repo.routers[LOC_A] = [
        MikrotikRouterRow(router_id=R1, name="Lobby hEX", status="online"),
        MikrotikRouterRow(router_id=R2, name="Roof", status="offline"),
    ]
    return repo


async def test_series_latest_and_stale() -> None:
    repo = _repo_with_venue()
    idx = int(START.timestamp()) // 1800
    repo.buckets = [
        CpuBucketRow(R1, idx + 2, 41.26, 77.0, 52.04),
        CpuBucketRow(R1, idx + 1, 12.0, 15.0, None),
    ]
    repo.latest[R1] = LatestReadingRow(R1, NOW - timedelta(minutes=4), 38.44, 51.0)
    repo.latest[R2] = LatestReadingRow(
        R2, NOW - timedelta(seconds=STALE_AFTER_SECONDS + 60), 9.0, None
    )
    out = await RouterCpuService(repo).get_router_cpu(
        organization_id=ORG_A, location_id=LOC_A, start=START, end=NOW, now=NOW
    )
    assert out.bucket_seconds == 1800
    assert out.high_cpu_percent == 80.0
    lobby, roof = out.routers
    assert lobby.router_name == "Lobby hEX"
    # Oldest first, rounded, gaps not zero-filled.
    assert [p.cpu_avg for p in lobby.points] == [12.0, 41.3]
    assert lobby.points[1].cpu_max == 77.0
    assert lobby.points[0].memory_avg is None
    assert (
        lobby.points[0].bucket_start
        == datetime.fromtimestamp((idx + 1) * 1800, tz=UTC).isoformat()
    )
    assert lobby.latest is not None and lobby.latest.cpu_usage_percent == 38.4
    assert lobby.latest.is_stale is False
    assert roof.points == []
    assert roof.latest is not None and roof.latest.is_stale is True


async def test_router_without_any_reading_has_null_latest() -> None:
    repo = _repo_with_venue()
    out = await RouterCpuService(repo).get_router_cpu(
        organization_id=ORG_A, location_id=LOC_A, start=START, end=NOW, now=NOW
    )
    assert [r.latest for r in out.routers] == [None, None]


async def test_venue_without_mikrotik_returns_empty_list() -> None:
    repo = _Repo()
    repo.locations[LOC_A] = ORG_A
    out = await RouterCpuService(repo).get_router_cpu(
        organization_id=ORG_A, location_id=LOC_A, start=START, end=NOW, now=NOW
    )
    assert out.routers == []


async def test_other_orgs_location_is_404_and_reads_nothing_else() -> None:
    repo = _repo_with_venue()
    with pytest.raises(LocationNotFoundError):
        await RouterCpuService(repo).get_router_cpu(
            organization_id=ORG_A, location_id=LOC_B, start=START, end=NOW
        )
    assert repo.calls == ["context"]


# ============================================================================
# 3. SQL shape
# ============================================================================


class _CapturingSession:
    def __init__(self) -> None:
        self.statements: list = []

    async def execute(self, statement):
        self.statements.append(statement)

        class _Result:
            def all(self_inner):
                return []

        return _Result()


def _sql(statement) -> str:
    return str(
        statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


async def test_router_roster_sql_is_tenant_and_vendor_scoped() -> None:
    session = _CapturingSession()
    await RouterCpuRepository(session).list_mikrotik_routers(
        organization_id=ORG_A, location_id=LOC_A
    )
    sql = _sql(session.statements[0])
    assert "routers.organization_id" in sql
    assert "routers.location_id" in sql
    assert "routers.is_deleted" in sql
    assert "'decommissioned'" in sql
    assert "'tplink_omada'" in sql and "'aruba_instant_on'" in sql
    assert "routers.vendor = 'mikrotik'" in sql


async def test_bucket_sql_groups_by_router_and_bucket_within_window() -> None:
    session = _CapturingSession()
    await RouterCpuRepository(session).get_cpu_buckets(
        router_ids=[R1], start=START, end=NOW, bucket_seconds=1800
    )
    sql = _sql(session.statements[0])
    assert "floor(EXTRACT(epoch FROM router_health_snapshots.recorded_at) /" in sql
    # The divisor is inline, not a bind parameter.
    compiled = session.statements[0].compile(dialect=postgresql.dialect())
    assert 1800 not in compiled.params.values()
    assert "1800" in str(compiled)
    # Grouped by the label, so Postgres sees one expression (two separately
    # bound copies of the divisor would be "must appear in GROUP BY").
    assert "GROUP BY router_health_snapshots.router_id, bucket" in sql
    assert "router_health_snapshots.recorded_at >=" in sql
    assert "router_health_snapshots.recorded_at <" in sql
    assert "max(router_health_snapshots.cpu_usage_percent)" in sql


async def test_no_router_ids_issue_no_snapshot_query() -> None:
    session = _CapturingSession()
    repo = RouterCpuRepository(session)
    assert (
        await repo.get_cpu_buckets(
            router_ids=[], start=START, end=NOW, bucket_seconds=1800
        )
        == []
    )
    assert await repo.get_latest_readings(router_ids=[], since=START, until=NOW) == {}
    assert session.statements == []


# ============================================================================
# 4. Route contract
# ============================================================================

BASE = "/api/v1/analytics/venue-insights"
PATH = "/router-cpu"


def _route(app):
    return next(
        r
        for r in app.routes
        if getattr(r, "path", None) == BASE + PATH and "GET" in r.methods
    )


def _dependency_calls(dependant) -> set:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


def _permission_deps(route) -> list[tuple[object, str, object]]:
    found = []
    for dep in _dependency_calls(route.dependant):
        cells = [c.cell_contents for c in (getattr(dep, "__closure__", None) or ())]
        keys = [c for c in cells if isinstance(c, str) and "." in c]
        if keys:
            scope = next((c for c in cells if isinstance(c, ScopeType)), None)
            found.append((dep, keys[0], scope))
    return found


def test_route_mounted_with_location_scope_and_required_org() -> None:
    from app.main import create_app

    route = _route(create_app())
    assert [(k, s) for _, k, s in _permission_deps(route)] == [
        ("analytics.read", ScopeType.LOCATION)
    ]
    calls = _dependency_calls(route.dependant)
    assert RequireOrganization in calls
    assert CurrentLocation in calls
    # Top level: the handler's org comes from RequireOrganization, never
    # CurrentOrganization (None = "every tenant" for a global caller).
    top_level = {d.call for d in route.dependant.dependencies}
    assert RequireOrganization in top_level
    assert CurrentOrganization not in top_level


def _app(repo, *, organization_id=ORG_A, scope_location_id=None) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(venue_router, prefix="/api/v1")
    for dep, _, _ in _permission_deps(_route(app)):
        app.dependency_overrides[dep] = lambda: None
    app.dependency_overrides[RequireOrganization] = lambda: organization_id
    app.dependency_overrides[CurrentLocation] = lambda: scope_location_id
    app.dependency_overrides[get_router_cpu_service] = lambda: RouterCpuService(repo)
    return app


async def _get(app: FastAPI, **params):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(BASE + PATH, params=params)


_WINDOW = {
    "start_date": START.isoformat().replace("+00:00", "Z"),
    "end_date": NOW.isoformat().replace("+00:00", "Z"),
}


async def test_http_other_orgs_location_is_404() -> None:
    repo = _repo_with_venue()
    response = await _get(_app(repo), location_id=str(LOC_B), **_WINDOW)
    assert response.status_code == 404, response.text
    assert repo.calls == ["context"]


async def test_http_sibling_site_outside_grant_is_403() -> None:
    repo = _repo_with_venue()
    repo.locations[LOC_A2] = ORG_A
    response = await _get(
        _app(repo, scope_location_id=LOC_A), location_id=str(LOC_A2), **_WINDOW
    )
    assert response.status_code == 403, response.text
    assert repo.calls == []


async def test_http_missing_location_is_422() -> None:
    response = await _get(_app(_repo_with_venue()), **_WINDOW)
    assert response.status_code == 422, response.text


async def test_http_envelope_shape() -> None:
    repo = _repo_with_venue()
    response = await _get(_app(repo), location_id=str(LOC_A), **_WINDOW)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert set(data) == {
        "location_id",
        "window_start",
        "window_end",
        "bucket_seconds",
        "stale_after_seconds",
        "high_cpu_percent",
        "routers",
    }
    assert data["bucket_seconds"] == 1800
    assert [r["router_name"] for r in data["routers"]] == ["Lobby hEX", "Roof"]
    assert set(data["routers"][0]) == {
        "router_id",
        "router_name",
        "status",
        "latest",
        "points",
    }

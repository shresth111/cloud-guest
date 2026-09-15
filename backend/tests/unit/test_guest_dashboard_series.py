"""``GET /guest-analytics/dashboard-series`` -- the customer dashboard's
range-aware aggregate.

The dashboard used to fetch one ``GET /guest-sessions`` page (capped at 100
rows) and bucket it in the browser, which undercounted any venue with more
than 100 sessions in the range and could not serve 7- or 30-day views.

Three layers are tested here:

1. **Pure helpers** -- bucket grid (with a tz offset), window validation, OS
   precedence.
2. **Behavioural scenarios** run against *two* repositories through the real
   ``GuestAnalyticsService``: ``_ReferenceRepository`` (a direct Python
   statement of the documented semantics, always runs) and the real
   ``GuestRepository`` SQL (runs when ``CLOUDGUEST_TEST_POSTGRES_URL`` points
   at a scratch Postgres database, e.g.
   ``postgresql+asyncpg://localhost/cg_dash_series_test``). This repo has no
   database-backed CI harness, so in CI only the reference half executes; the
   Postgres half is what proves the SQL matches it.
3. **Route contract** -- path, permission key, org/location dependencies,
   422s, and handler-level tenant scoping.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.common.exceptions import register_exception_handlers
from app.domains.guest.constants import (
    DASHBOARD_OS_NAMES,
    DashboardSeriesBucket,
)
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.exceptions import InvalidDashboardSeriesRangeError
from app.domains.guest.models import GuestSession
from app.domains.guest.repository import DashboardSeriesAggregate, GuestRepository
from app.domains.guest.router import analytics_router
from app.domains.guest.service import GuestAnalyticsService
from app.domains.guest.validators import (
    classify_dashboard_os,
    dashboard_series_bucket_starts,
    validate_dashboard_series_window,
)
from app.domains.rbac.dependencies import (
    CurrentLocation,
    RequireOrganization,
)

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
IST = 330

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
LOC_A = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_B = uuid.UUID("00000000-0000-0000-0000-0000000000b1")


def _utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


# ============================================================================
# 1. Pure helpers
# ============================================================================


class TestBucketGrid:
    def test_hour_buckets_align_to_local_hour_for_ist(self) -> None:
        # 00:00 IST on 11 Sep is 18:30Z on 10 Sep. Start mid-hour locally.
        starts = dashboard_series_bucket_starts(
            start=_utc(2026, 9, 10, 18, 50),
            end=_utc(2026, 9, 10, 21, 30),
            bucket=DashboardSeriesBucket.HOUR,
            tz_offset_minutes=IST,
        )
        assert starts == [
            _utc(2026, 9, 10, 18, 30),
            _utc(2026, 9, 10, 19, 30),
            _utc(2026, 9, 10, 20, 30),
        ]

    def test_day_buckets_align_to_local_midnight_for_ist(self) -> None:
        starts = dashboard_series_bucket_starts(
            start=_utc(2026, 9, 1, 18, 30),
            end=_utc(2026, 9, 8, 18, 30),
            bucket=DashboardSeriesBucket.DAY,
            tz_offset_minutes=IST,
        )
        assert len(starts) == 7
        assert starts[0] == _utc(2026, 9, 1, 18, 30)
        assert starts[-1] == _utc(2026, 9, 7, 18, 30)
        assert all(b - a == DAY for a, b in zip(starts, starts[1:], strict=False))

    def test_negative_offset_and_utc(self) -> None:
        starts = dashboard_series_bucket_starts(
            start=_utc(2026, 9, 10, 3, 0),
            end=_utc(2026, 9, 11, 3, 0),
            bucket=DashboardSeriesBucket.DAY,
            tz_offset_minutes=-300,
        )
        # 03:00Z is 22:00 on 9 Sep at UTC-5; local midnight 9 Sep is 05:00Z 9 Sep.
        assert starts == [_utc(2026, 9, 9, 5, 0), _utc(2026, 9, 10, 5, 0)]
        assert dashboard_series_bucket_starts(
            start=_utc(2026, 9, 10),
            end=_utc(2026, 9, 10, 3),
            bucket=DashboardSeriesBucket.HOUR,
            tz_offset_minutes=0,
        ) == [_utc(2026, 9, 10, 0), _utc(2026, 9, 10, 1), _utc(2026, 9, 10, 2)]


class TestWindowValidation:
    def test_end_equal_to_start_is_rejected(self) -> None:
        with pytest.raises(InvalidDashboardSeriesRangeError) as exc:
            validate_dashboard_series_window(_utc(2026, 9, 1), _utc(2026, 9, 1))
        assert exc.value.status_code == 422

    def test_end_before_start_is_rejected(self) -> None:
        with pytest.raises(InvalidDashboardSeriesRangeError):
            validate_dashboard_series_window(_utc(2026, 9, 2), _utc(2026, 9, 1))

    def test_exactly_31_days_is_accepted(self) -> None:
        validate_dashboard_series_window(_utc(2026, 8, 1), _utc(2026, 9, 1))

    def test_longer_than_31_days_is_rejected(self) -> None:
        with pytest.raises(InvalidDashboardSeriesRangeError) as exc:
            validate_dashboard_series_window(
                _utc(2026, 8, 1), _utc(2026, 9, 1, 0, 0, 1)
            )
        assert exc.value.status_code == 422


# (user_agent, expected) -- precedence is the point of most rows.
OS_CASES: list[tuple[str | None, str]] = [
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)", "iOS"),
    ("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)", "iOS"),  # iOS beats macOS
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8)", "Android"),  # beats Linux
    ("Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1)", "Android"),  # beats Win
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS"),
    ("MAC OS thing", "macOS"),  # case-insensitive
    ("Mozilla/5.0 (X11; Linux x86_64)", "Linux"),
    ("curl/8.4.0", "Other"),
    ("", "Other"),
    (None, "Other"),
]


@pytest.mark.parametrize(("user_agent", "expected"), OS_CASES)
def test_os_classifier_precedence(user_agent: str | None, expected: str) -> None:
    assert classify_dashboard_os(user_agent) == expected


# ============================================================================
# 2. Behavioural scenarios: reference repository and real SQL
# ============================================================================


class _ReferenceRepository:
    """The documented semantics, written as plainly as possible over
    in-memory rows. Not a fake to make tests pass -- the Postgres run of the
    same scenarios checks the SQL against it."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.calls: list[dict] = []

    async def add(self, **row) -> None:
        self.rows.append(row)

    async def get_dashboard_series(
        self,
        *,
        organization_id,
        location_id,
        start,
        end,
        first_bucket_start,
        bucket_seconds,
        bucket_count,
        now,
    ) -> DashboardSeriesAggregate:
        self.calls.append({"organization_id": organization_id})
        rows = [
            r
            for r in self.rows
            if r["organization_id"] == organization_id
            and r["location_id"] == location_id
            and not r.get("is_deleted", False)
        ]
        width = timedelta(seconds=bucket_seconds)
        started = [r for r in rows if start <= r["started_at"] < end]
        arrivals: dict[int, int] = {}
        online: dict[int, int] = {}
        for i in range(bucket_count):
            lo = max(first_bucket_start + i * width, start)
            hi = min(first_bucket_start + (i + 1) * width, end)
            a = sum(1 for r in rows if lo <= r["started_at"] < hi)
            o = sum(
                1 for r in rows if r["started_at"] < hi and (r["ended_at"] or now) > lo
            )
            if a:
                arrivals[i] = a
            if o:
                online[i] = o
        durations = [
            max(
                ((r["ended_at"] or min(now, end)) - r["started_at"]).total_seconds(),
                0,
            )
            for r in started
        ]
        os_counts: dict[str, int] = {}
        for r in started:
            name = classify_dashboard_os(r.get("user_agent"))
            os_counts[name] = os_counts.get(name, 0) + 1
        return DashboardSeriesAggregate(
            guests=len({r["guest_id"] or r["device_id"] for r in started}),
            sessions=len(started),
            avg_session_seconds=sum(durations) / len(durations) if durations else None,
            arrivals_by_bucket=arrivals,
            online_by_bucket=online,
            os_counts=os_counts,
        )


_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")


class _PostgresHarness:
    """Real ``GuestRepository`` over a throwaway schema holding only
    ``guest_sessions`` (no foreign keys, so no parent rows are needed)."""

    def __init__(self, session, repository) -> None:
        self.session = session
        self.repository = repository

    async def add(self, **row) -> None:
        from sqlalchemy import insert

        now = datetime.now(UTC)
        values = {
            "id": uuid.uuid4(),
            "created_at": now,
            "updated_at": now,
            "is_deleted": False,
            "version": 1,
            "router_id": uuid.uuid4(),
            "auth_method": "otp_sms",
            "status": "active" if row.get("ended_at") is None else "disconnected",
            "last_activity_at": row["started_at"],
            "bytes_uploaded": 0,
            "bytes_downloaded": 0,
            **row,
        }
        await self.session.execute(insert(GuestSession.__table__).values(**values))
        await self.session.flush()


@pytest.fixture(params=["reference", "postgres"])
async def harness(request):
    if request.param == "reference":
        repo = _ReferenceRepository()
        yield repo, repo
        return
    if not _PG_URL:
        pytest.skip("CLOUDGUEST_TEST_POSTGRES_URL not set")
    from sqlalchemy import Column, MetaData, Table, text
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    schema = f"dash_series_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL)
    async with admin.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    metadata = MetaData()
    Table(
        "guest_sessions",
        metadata,
        *[
            Column(c.name, c.type, nullable=c.nullable, primary_key=c.primary_key)
            for c in GuestSession.__table__.columns
        ],
    )
    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        async with AsyncSession(engine) as session:
            harness = _PostgresHarness(session, GuestRepository(session))
            yield harness, harness.repository
    finally:
        await engine.dispose()
        async with admin.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


def _session(
    started_at: datetime,
    ended_at: datetime | None = None,
    *,
    organization_id: uuid.UUID = ORG_A,
    location_id: uuid.UUID = LOC_A,
    guest_id: uuid.UUID | None = None,
    user_agent: str | None = None,
    is_deleted: bool = False,
) -> dict:
    return {
        "organization_id": organization_id,
        "location_id": location_id,
        "guest_id": guest_id or uuid.uuid4(),
        "device_id": None,
        "started_at": started_at,
        "ended_at": ended_at,
        "user_agent": user_agent,
        "is_deleted": is_deleted,
    }


# 00:00 IST 11 Sep 2026 == 18:30Z 10 Sep.
IST_MIDNIGHT = _utc(2026, 9, 10, 18, 30)
FAR_FUTURE = _utc(2027, 1, 1)


def _series(result) -> list[tuple[datetime, int, int]]:
    return [(p.bucket_start, p.arrivals, p.online) for p in result.series]


class TestScenarios:
    async def test_hour_zero_fill_with_ist_offset(self, harness) -> None:
        h, repo = harness
        await h.add(
            **_session(
                IST_MIDNIGHT + 75 * timedelta(minutes=1),
                IST_MIDNIGHT + 160 * timedelta(minutes=1),
            )
        )
        result = await GuestAnalyticsService(repo).get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=IST_MIDNIGHT,
            end=IST_MIDNIGHT + 6 * HOUR,
            bucket=DashboardSeriesBucket.HOUR,
            tz_offset_minutes=IST,
            now=FAR_FUTURE,
        )
        # started 01:15 IST, ended 02:40 IST
        assert _series(result) == [
            (IST_MIDNIGHT, 0, 0),
            (IST_MIDNIGHT + HOUR, 1, 1),
            (IST_MIDNIGHT + 2 * HOUR, 0, 1),
            (IST_MIDNIGHT + 3 * HOUR, 0, 0),
            (IST_MIDNIGHT + 4 * HOUR, 0, 0),
            (IST_MIDNIGHT + 5 * HOUR, 0, 0),
        ]
        assert result.sessions == 1
        assert result.guests == 1
        assert result.avg_session_seconds == 85 * 60
        assert result.peak_online == 1

    async def test_day_zero_fill_with_ist_offset(self, harness) -> None:
        h, repo = harness
        # 03:30 IST 2 Sep -> 01:30 IST 4 Sep: spans three local days.
        await h.add(**_session(_utc(2026, 9, 1, 22, 0), _utc(2026, 9, 3, 20, 0)))
        result = await GuestAnalyticsService(repo).get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=_utc(2026, 9, 1, 18, 30),
            end=_utc(2026, 9, 8, 18, 30),
            bucket=DashboardSeriesBucket.DAY,
            tz_offset_minutes=IST,
            now=FAR_FUTURE,
        )
        assert [(p.arrivals, p.online) for p in result.series] == [
            (1, 1),
            (0, 1),
            (0, 1),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ]
        assert result.series[0].bucket_start == _utc(2026, 9, 1, 18, 30)
        assert result.series[6].bucket_start == _utc(2026, 9, 7, 18, 30)

    async def test_online_overlap_at_exact_bucket_boundaries(self, harness) -> None:
        h, repo = harness
        b = IST_MIDNIGHT
        # Ends exactly at bucket 1's start: online in bucket 0 only.
        await h.add(**_session(b + timedelta(minutes=10), b + HOUR))
        # Starts exactly at bucket 1's start: arrival + online in bucket 1 only.
        await h.add(**_session(b + HOUR, b + HOUR + timedelta(minutes=5)))
        # Spans buckets 1..3, ending mid-bucket 3.
        await h.add(
            **_session(b + 90 * timedelta(minutes=1), b + 200 * timedelta(minutes=1))
        )
        # Started before the window, ended inside bucket 0: online, no arrival.
        await h.add(**_session(b - 2 * HOUR, b + timedelta(minutes=1)))
        # Started and ended before the window: nothing.
        await h.add(**_session(b - 3 * HOUR, b - 2 * HOUR))
        result = await GuestAnalyticsService(repo).get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=b,
            end=b + 4 * HOUR,
            bucket=DashboardSeriesBucket.HOUR,
            tz_offset_minutes=IST,
            now=FAR_FUTURE,
        )
        assert [(p.arrivals, p.online) for p in result.series] == [
            (1, 2),
            (2, 2),
            (0, 1),
            (0, 1),
        ]
        assert result.sessions == 3
        assert result.peak_online == 2

    async def test_open_session_is_not_counted_past_now(self, harness) -> None:
        h, repo = harness
        b = IST_MIDNIGHT
        now = b + 2 * HOUR + timedelta(minutes=30)  # inside bucket 2
        await h.add(**_session(b + timedelta(minutes=30)))  # open, started in window
        await h.add(**_session(b - 5 * HOUR))  # open, started before window
        result = await GuestAnalyticsService(repo).get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=b,
            end=b + 6 * HOUR,
            bucket=DashboardSeriesBucket.HOUR,
            tz_offset_minutes=IST,
            now=now,
        )
        assert [p.online for p in result.series] == [2, 2, 2, 0, 0, 0]
        assert [p.arrivals for p in result.series] == [1, 0, 0, 0, 0, 0]
        # Only the in-window session counts, measured to min(now, end).
        assert result.sessions == 1
        assert result.avg_session_seconds == 2 * 3600

    async def test_os_breakdown_precedence_omits_zeros_and_sorts(self, harness) -> None:
        h, repo = harness
        b = IST_MIDNIGHT
        for index, (user_agent, _) in enumerate(OS_CASES):
            await h.add(
                **_session(
                    b + index * timedelta(minutes=1), b + HOUR, user_agent=user_agent
                )
            )
        result = await GuestAnalyticsService(repo).get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=b,
            end=b + DAY,
            bucket=DashboardSeriesBucket.DAY,
            tz_offset_minutes=IST,
            now=FAR_FUTURE,
        )
        assert result.os_breakdown == [
            ("Other", 3),
            ("iOS", 2),
            ("Android", 2),
            ("macOS", 2),
            ("Windows", 1),
            ("Linux", 1),
        ]
        assert all(count > 0 for _, count in result.os_breakdown)
        assert {name for name, _ in result.os_breakdown} <= set(DASHBOARD_OS_NAMES)

    async def test_guests_are_distinct_and_empty_window_has_null_average(
        self, harness
    ) -> None:
        h, repo = harness
        b = IST_MIDNIGHT
        guest = uuid.uuid4()
        await h.add(
            **_session(
                b + timedelta(minutes=1), b + timedelta(minutes=11), guest_id=guest
            )
        )
        await h.add(
            **_session(
                b + timedelta(minutes=20), b + timedelta(minutes=50), guest_id=guest
            )
        )
        service = GuestAnalyticsService(repo)
        result = await service.get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=b,
            end=b + HOUR,
            bucket=DashboardSeriesBucket.HOUR,
            now=FAR_FUTURE,
        )
        assert (result.guests, result.sessions) == (1, 2)
        assert result.avg_session_seconds == 20 * 60
        empty = await service.get_dashboard_series(
            organization_id=ORG_A,
            location_id=LOC_A,
            start=b + DAY,
            end=b + 2 * DAY,
            bucket=DashboardSeriesBucket.HOUR,
            tz_offset_minutes=IST,
            now=FAR_FUTURE,
        )
        assert empty.avg_session_seconds is None
        assert (empty.guests, empty.sessions, empty.peak_online) == (0, 0, 0)
        assert len(empty.series) == 24
        assert empty.os_breakdown == []

    async def test_tenant_isolation_by_organization_and_location(self, harness) -> None:
        h, repo = harness
        b = IST_MIDNIGHT
        await h.add(
            **_session(
                b + timedelta(minutes=5),
                b + timedelta(minutes=50),
                organization_id=ORG_B,
                location_id=LOC_B,
            )
        )
        await h.add(
            **_session(
                b + timedelta(minutes=6),
                b + timedelta(minutes=50),
                organization_id=ORG_B,
                location_id=LOC_B,
                is_deleted=True,
            )
        )
        service = GuestAnalyticsService(repo)

        async def run(org, loc):
            return await service.get_dashboard_series(
                organization_id=org,
                location_id=loc,
                start=b,
                end=b + HOUR,
                bucket=DashboardSeriesBucket.HOUR,
                now=FAR_FUTURE,
            )

        # Org A's caller naming org B's location sees nothing.
        foreign = await run(ORG_A, LOC_B)
        assert (foreign.sessions, foreign.guests, foreign.peak_online) == (0, 0, 0)
        assert foreign.os_breakdown == []
        # Mismatched pair in the other direction also sees nothing.
        assert (await run(ORG_B, LOC_A)).sessions == 0
        # The owner sees its one live (non-deleted) session.
        own = await run(ORG_B, LOC_B)
        assert (own.sessions, own.peak_online) == (1, 1)


# ============================================================================
# 3. Route contract
# ============================================================================

PATH = "/api/v1/guest-analytics/dashboard-series"


def _route(app, path: str, method: str):
    return next(
        r
        for r in app.routes
        if getattr(r, "path", None) == path and method in getattr(r, "methods", set())
    )


def _dependency_calls(dependant) -> set:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


def _permission_keys(route) -> list[str]:
    keys = []
    for dep in _dependency_calls(route.dependant):
        for cell in getattr(dep, "__closure__", None) or ():
            if isinstance(cell.cell_contents, str) and "." in cell.cell_contents:
                keys.append(cell.cell_contents)
    return keys


def test_route_is_mounted_beside_summary_with_guest_sessions_read() -> None:
    from app.main import create_app

    app = create_app()
    route = _route(app, PATH, "GET")
    summary = _route(app, "/api/v1/guest-analytics/summary", "GET")
    assert _permission_keys(route) == ["guest_sessions.read"]
    assert _permission_keys(summary) == ["analytics.read"]
    calls = _dependency_calls(route.dependant)
    assert RequireOrganization in calls
    assert CurrentLocation in calls


def _permission_dependency(app: FastAPI):
    route = _route(app, "/api/v1/guest-analytics/dashboard-series", "GET")
    return next(
        dep
        for dep in _dependency_calls(route.dependant)
        if "guest_sessions.read"
        in [c.cell_contents for c in (getattr(dep, "__closure__", None) or ())]
    )


def _app(repo, *, organization_id=ORG_A, scope_location_id=None) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(analytics_router, prefix="/api/v1")
    app.dependency_overrides[_permission_dependency(app)] = lambda: None
    app.dependency_overrides[RequireOrganization] = lambda: organization_id
    app.dependency_overrides[CurrentLocation] = lambda: scope_location_id
    app.dependency_overrides[get_guest_analytics_service] = (
        lambda: GuestAnalyticsService(repo)
    )
    return app


async def _get(app: FastAPI, **params):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(PATH, params=params)


def _params(**overrides) -> dict:
    params = {
        "location_id": str(LOC_A),
        "start_date": "2026-09-10T18:30:00Z",
        "end_date": "2026-09-11T00:30:00Z",
        "bucket": "hour",
        "tz_offset_minutes": IST,
    }
    params.update(overrides)
    return params


class TestHttp:
    async def test_window_longer_than_31_days_is_422(self) -> None:
        response = await _get(
            _app(_ReferenceRepository()),
            **_params(
                start_date="2026-08-01T00:00:00Z",
                end_date="2026-09-02T00:00:00Z",
                bucket="day",
            ),
        )
        assert response.status_code == 422, response.text

    async def test_inverted_window_is_422(self) -> None:
        response = await _get(
            _app(_ReferenceRepository()),
            **_params(end_date="2026-09-10T18:30:00Z"),
        )
        assert response.status_code == 422, response.text

    @pytest.mark.parametrize(
        "overrides",
        [
            {"bucket": "week"},
            {"tz_offset_minutes": 841},
            {"tz_offset_minutes": -721},
            {"location_id": None},
        ],
    )
    async def test_invalid_params_are_422(self, overrides) -> None:
        params = {k: v for k, v in _params(**overrides).items() if v is not None}
        response = await _get(_app(_ReferenceRepository()), **params)
        assert response.status_code == 422, response.text

    async def test_location_outside_callers_location_scope_is_403(self) -> None:
        response = await _get(
            _app(_ReferenceRepository(), scope_location_id=LOC_A),
            **_params(location_id=str(LOC_B)),
        )
        assert response.status_code == 403, response.text

    async def test_other_orgs_location_returns_no_data_and_scopes_by_header_org(
        self,
    ) -> None:
        repo = _ReferenceRepository()
        await repo.add(
            **_session(
                IST_MIDNIGHT + timedelta(minutes=5),
                IST_MIDNIGHT + HOUR,
                organization_id=ORG_B,
                location_id=LOC_B,
            )
        )
        response = await _get(
            _app(repo, organization_id=ORG_A), **_params(location_id=str(LOC_B))
        )
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert (data["sessions"], data["guests"], data["peak_online"]) == (0, 0, 0)
        assert repo.calls == [{"organization_id": ORG_A}]

    async def test_response_shape(self) -> None:
        repo = _ReferenceRepository()
        b = IST_MIDNIGHT
        await repo.add(
            **_session(
                b + 75 * timedelta(minutes=1),
                b + 160 * timedelta(minutes=1),
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_5)",
            )
        )
        await repo.add(
            **_session(
                b + 80 * timedelta(minutes=1),
                b + 100 * timedelta(minutes=1),
                user_agent="Mozilla/5.0 (Linux; Android 14)",
            )
        )
        await repo.add(
            **_session(
                b + 200 * timedelta(minutes=1),
                None,
                user_agent="Mozilla/5.0 (Linux; Android 13)",
            )
        )
        response = await _get(_app(repo), **_params())
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["success"] is True
        data = body["data"]
        assert set(data) == {
            "start",
            "end",
            "bucket",
            "guests",
            "sessions",
            "avg_session_seconds",
            "peak_online",
            "series",
            "os_breakdown",
        }
        assert data["bucket"] == "hour"
        assert data["start"] == "2026-09-10T18:30:00Z"
        assert data["end"] == "2026-09-11T00:30:00Z"
        assert data["sessions"] == 3
        assert data["guests"] == 3
        assert isinstance(data["avg_session_seconds"], int)
        assert data["peak_online"] == 2
        assert [p["bucket_start"] for p in data["series"]] == [
            "2026-09-10T18:30:00Z",
            "2026-09-10T19:30:00Z",
            "2026-09-10T20:30:00Z",
            "2026-09-10T21:30:00Z",
            "2026-09-10T22:30:00Z",
            "2026-09-10T23:30:00Z",
        ]
        assert [(p["arrivals"], p["online"]) for p in data["series"]] == [
            (0, 0),
            (2, 2),
            (0, 1),
            (1, 1),
            (0, 1),
            (0, 1),
        ]
        assert data["os_breakdown"] == [
            {"name": "Android", "count": 2},
            {"name": "iOS", "count": 1},
        ]

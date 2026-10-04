"""P1-G: analytics scores stop judging Aruba Instant On (NAS-only) rows by a
heartbeat they never send. MikroTik / Omada results are unchanged.

* health score: router counts requested with ``exclude_nas_only=True``
  (the SQL filter is ``vendor NOT IN NAS_ONLY_VENDORS``; a fleet with no
  NAS-only row reads identically);
* ``/analytics/network`` availability: NAS-only rows excluded; an org with
  only NAS-only rows reads ``None`` (not measured) instead of 0%;
* ``/analytics/routers``: ``internet_available`` is ``None`` for a NAS-only
  row, unchanged True/False for every other row;
* router failure risk: NAS-only rows are not assessed (no health history
  can exist for them).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.domains.analytics.repository import RouterSummaryRow
from app.domains.router.enums import RouterStatus
from tests.unit.test_analytics_forecast_insights import (
    _FakePart4Repository,
    _forecast_settings,
)
from tests.unit.test_analytics_forecast_insights import (
    _FakeRedis as _ForecastRedis,
)
from tests.unit.test_analytics_forecast_insights import (
    _org_scope_resolver as _forecast_scope,
)
from tests.unit.test_analytics_router_network_guest_auth import (
    _FakeDomainAnalyticsRepository,
    _make_service,
)

NOW = datetime.now(UTC)


def _row(name: str, *, vendor: str, status: str, seen: datetime | None):  # noqa: ANN202
    return RouterSummaryRow(
        router_id=uuid.uuid4(),
        router_name=name,
        location_id=uuid.uuid4(),
        status=status,
        last_seen_at=seen,
        vendor=vendor,
    )


MIKROTIK = _row("hEX", vendor="mikrotik", status=RouterStatus.ONLINE.value, seen=NOW)
OMADA = _row(
    "Omada", vendor="tplink_omada", status=RouterStatus.OFFLINE.value, seen=NOW
)
ARUBA = _row(
    "AP21",
    vendor="aruba_instant_on",
    status=RouterStatus.PENDING_PROVISIONING.value,
    seen=None,
)


async def _network(routers):  # noqa: ANN001, ANN202
    org = uuid.uuid4()
    svc = _make_service(
        _FakeDomainAnalyticsRepository(routers=routers), organization_id=org
    )
    return await svc.get_network_analytics(
        uuid.uuid4(), org, location_id=None, start=NOW - timedelta(days=1), end=NOW
    )


class TestNetworkAvailability:
    async def test_mikrotik_omada_unchanged(self) -> None:
        result = await _network([MIKROTIK, OMADA])
        avail = result.network_availability
        assert (avail.available_router_count, avail.total_router_count) == (1, 2)

    async def test_aruba_excluded_from_ratio(self) -> None:
        result = await _network([MIKROTIK, OMADA, ARUBA])
        avail = result.network_availability
        assert (avail.available_router_count, avail.total_router_count) == (1, 2)

    async def test_aruba_only_not_measured(self) -> None:
        avail = (await _network([ARUBA])).network_availability
        assert avail.total_router_count == 0
        assert avail.availability_percent is None


class TestRouterAnalytics:
    async def test_internet_available_none_only_for_nas_only(self) -> None:
        org = uuid.uuid4()
        svc = _make_service(
            _FakeDomainAnalyticsRepository(routers=[MIKROTIK, OMADA, ARUBA]),
            organization_id=org,
        )
        result = await svc.get_router_analytics(
            uuid.uuid4(), org, location_id=None, start=NOW - timedelta(days=1), end=NOW
        )
        by_name = {r.router_name: r for r in result.routers}
        assert by_name["hEX"].internet_available is True
        assert by_name["Omada"].internet_available is False
        assert by_name["AP21"].internet_available is None
        # Still listed, with its session-derived bandwidth intact.
        assert by_name["AP21"].bandwidth_total_bytes == 0


class TestHealthScore:
    async def test_health_score_asks_for_nas_only_exclusion(self) -> None:
        from app.domains.analytics.dashboard_service import DashboardService

        calls: list[dict] = []

        class _Repo:
            async def count_routers_by_status(self, **kw):  # noqa: ANN003, ANN202
                calls.append(kw)
                return []  # an Aruba-only org once its AP is excluded

            async def get_open_alert_counts_by_severity(self, **kw):  # noqa: ANN003, ANN202
                return {}

            async def get_latest_snapshot(self, **kw):  # noqa: ANN003, ANN202
                return None

            async def list_snapshots(self, **kw):  # noqa: ANN003, ANN202
                return [], None

        svc = DashboardService.__new__(DashboardService)
        svc.repository = _Repo()
        result = await svc._compute_health_score(uuid.uuid4(), NOW)
        assert calls and calls[0]["exclude_nas_only"] is True
        assert result.router_health_component == 100.0  # neutral, not 0

    async def test_sql_filter_only_when_asked(self) -> None:
        """The statement gains the vendor filter only with the kwarg; the
        default (every other caller) compiles exactly as before."""
        from sqlalchemy.dialects import postgresql

        from app.domains.analytics.repository import AnalyticsRepository

        captured: list[str] = []

        class _Result:
            def all(self):  # noqa: ANN202
                return []

        class _Session:
            async def execute(self, stmt):  # noqa: ANN001, ANN202
                captured.append(str(stmt.compile(dialect=postgresql.dialect())))
                return _Result()

        repo = AnalyticsRepository.__new__(AnalyticsRepository)
        repo.session = _Session()
        await repo.count_routers_by_status(organization_id=uuid.uuid4())
        await repo.count_routers_by_status(
            organization_id=uuid.uuid4(), exclude_nas_only=True
        )
        default_sql, excl_sql = captured
        assert "routers.vendor NOT IN" not in default_sql
        assert "routers.vendor NOT IN" in excl_sql


class TestFailureRisk:
    async def test_nas_only_not_assessed(self) -> None:
        from app.domains.analytics.forecast_service import ForecastService

        org = uuid.uuid4()
        repo = _FakePart4Repository(
            routers=[MIKROTIK, ARUBA],
            health_history={},
            alert_counts_by_router={},
        )
        svc = ForecastService(
            repo, _forecast_scope(org), _ForecastRedis(), _forecast_settings()
        )
        result = await svc.get_router_failure_risk(uuid.uuid4(), org, location_id=None)
        assert [r.router_name for r in result.routers] == ["hEX"]

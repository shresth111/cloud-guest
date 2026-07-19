"""Unit tests for BE-012 Part 4 (Business Analytics + Forecast/Insight/Trend
Engines): the ordinary-least-squares linear-regression math against known,
hand-computed series (a perfectly linear series forecasts exactly, with a
real R^2 of 1.0), the Router Failure Risk heuristic's firing/not-firing
against constructed ``RouterHealthSnapshot``-shaped fixture trends, every
Insight Engine rule firing/not-firing against constructed threshold-crossing
and threshold-not-crossing fixtures, Business Analytics' honest placeholders
and its two real queries (Customer Growth, Plan Distribution), the Trend
Engine's shared helpers, and tenant/scope isolation across all three new
services.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_analytics_router_network_guest_auth.py``'s own module
docstring) -- every fake below is a small, hand-rolled stand-in for the
narrow protocol it satisfies, no live Postgres/Redis anywhere in this test
suite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.domains.analytics.business_schemas import PlanDistributionResponse
from app.domains.analytics.business_service import BusinessAnalyticsService
from app.domains.analytics.dashboard_scope import DashboardScopeResolver
from app.domains.analytics.exceptions import DashboardScopeForbiddenError
from app.domains.analytics.forecast import (
    LinearFit,
    RouterFailureRiskResult,
    assess_router_failure_risk,
    fit_linear_trend,
    forecast_linear_series,
    project_upward_threshold_crossing,
)
from app.domains.analytics.forecast_service import ForecastService
from app.domains.analytics.insight_service import InsightService
from app.domains.analytics.insights import (
    InsightSeverity,
    rule_customer_growth,
    rule_guest_growth,
    rule_location_guest_volume_drop,
    rule_offline_routers,
    rule_persistent_critical_alerts,
    rule_plan_distribution_coverage,
    rule_rising_router_cpu,
)
from app.domains.analytics.repository import RouterHealthHistoryRow, RouterStatusRow
from app.domains.analytics.trends import (
    TrendPoint,
    build_growth_trend,
    compute_snapshot_metric_growth,
    count_trailing_consecutive_increases,
    extract_metric_series,
    growth_point_response,
)
from app.domains.rbac.enums import ScopeType
from app.domains.router.enums import RouterStatus

# ============================================================================
# forecast.fit_linear_trend -- OLS math against known, hand-computed series
# ============================================================================


def test_fit_linear_trend_perfect_line_exact_slope_intercept_and_r_squared():
    points = [(0.0, 10.0), (1.0, 20.0), (2.0, 30.0), (3.0, 40.0)]
    fit = fit_linear_trend(points)
    assert fit is not None
    assert fit.slope == pytest.approx(10.0)
    assert fit.intercept == pytest.approx(10.0)
    assert fit.r_squared == pytest.approx(1.0)
    assert fit.point_count == 4


def test_fit_linear_trend_flat_series_zero_slope_and_perfect_fit():
    points = [(0.0, 5.0), (1.0, 5.0), (2.0, 5.0)]
    fit = fit_linear_trend(points)
    assert fit is not None
    assert fit.slope == pytest.approx(0.0)
    assert fit.intercept == pytest.approx(5.0)
    assert fit.r_squared == pytest.approx(1.0)


def test_fit_linear_trend_noisy_series_r_squared_between_0_and_1():
    # A clear upward trend with one noisy point -- not a perfect fit, but a
    # real, non-trivial R^2.
    points = [(0.0, 10.0), (1.0, 19.0), (2.0, 32.0), (3.0, 39.0)]
    fit = fit_linear_trend(points)
    assert fit is not None
    assert 0.0 < fit.r_squared < 1.0


def test_fit_linear_trend_insufficient_points_is_none():
    assert fit_linear_trend([]) is None
    assert fit_linear_trend([(0.0, 1.0)]) is None


def test_fit_linear_trend_no_x_variance_is_none():
    """Every point shares the same x -- a vertical 'line' has no
    slope/intercept form."""
    assert fit_linear_trend([(5.0, 1.0), (5.0, 2.0), (5.0, 3.0)]) is None


# ============================================================================
# forecast.forecast_linear_series -- wraps fit_linear_trend over a real
# TrendPoint series, projecting forward
# ============================================================================


def _daily_points(values: list[float], *, start: datetime) -> list[TrendPoint]:
    return [
        TrendPoint(timestamp=start + timedelta(days=i), value=v)
        for i, v in enumerate(values)
    ]


def test_forecast_linear_series_projects_exactly_for_a_perfectly_linear_series():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    series = _daily_points([10.0, 20.0, 30.0, 40.0], start=start)
    result = forecast_linear_series(series, forecast_days=2, min_points=3)
    assert result.available is True
    assert result.fit is not None
    assert result.fit.slope == pytest.approx(10.0)
    assert result.fit.r_squared == pytest.approx(1.0)
    assert len(result.projected_points) == 2
    # day 4 -> 50, day 5 -> 60 (slope=10, intercept=10)
    assert result.projected_points[0].value == pytest.approx(50.0)
    assert result.projected_points[1].value == pytest.approx(60.0)
    assert result.projected_points[0].timestamp == start + timedelta(days=4)


def test_forecast_linear_series_unavailable_with_too_few_points():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    series = _daily_points([10.0, 20.0], start=start)
    result = forecast_linear_series(series, forecast_days=3, min_points=3)
    assert result.available is False
    assert result.fit is None
    assert result.projected_points == []
    assert "3 required" in (result.message or "")


# ============================================================================
# forecast.project_upward_threshold_crossing -- Capacity Prediction's math
# ============================================================================


def test_threshold_crossing_already_reached_reports_zero_days():
    fit = LinearFit(slope=1.0, intercept=0.0, r_squared=1.0, point_count=5)
    now = datetime(2026, 1, 5, tzinfo=UTC)
    result = project_upward_threshold_crossing(
        fit=fit, last_x=4.0, last_timestamp=now, current_value=50.0, threshold=40.0
    )
    assert result.available is True
    assert result.days_until_crossing == 0
    assert result.projected_crossing_date == now


def test_threshold_crossing_computes_correct_future_date():
    # slope=10/day, intercept=10 -- current value at x=3 is 40; solving for
    # x where value == 100 gives x=9, i.e. 6 days after the last observation.
    fit = LinearFit(slope=10.0, intercept=10.0, r_squared=1.0, point_count=4)
    last_timestamp = datetime(2026, 1, 4, tzinfo=UTC)
    result = project_upward_threshold_crossing(
        fit=fit,
        last_x=3.0,
        last_timestamp=last_timestamp,
        current_value=40.0,
        threshold=100.0,
    )
    assert result.available is True
    assert result.days_until_crossing == 6
    assert result.projected_crossing_date == last_timestamp + timedelta(days=6)


def test_threshold_crossing_flat_trend_never_reaches_is_unavailable():
    fit = LinearFit(slope=0.0, intercept=40.0, r_squared=1.0, point_count=5)
    result = project_upward_threshold_crossing(
        fit=fit,
        last_x=4.0,
        last_timestamp=datetime(2026, 1, 5, tzinfo=UTC),
        current_value=40.0,
        threshold=100.0,
    )
    assert result.available is False
    assert result.days_until_crossing is None


def test_threshold_crossing_declining_trend_never_reaches_is_unavailable():
    fit = LinearFit(slope=-2.0, intercept=50.0, r_squared=1.0, point_count=5)
    result = project_upward_threshold_crossing(
        fit=fit,
        last_x=4.0,
        last_timestamp=datetime(2026, 1, 5, tzinfo=UTC),
        current_value=42.0,
        threshold=100.0,
    )
    assert result.available is False


# ============================================================================
# forecast.assess_router_failure_risk -- the heuristic risk FLAG, firing/
# not-firing per real, cited signal (never a fabricated probability)
# ============================================================================

_ROUTER_ID = uuid.uuid4()


def _cpu_history(values: list[float], *, start: datetime) -> list[TrendPoint]:
    return _daily_points(values, start=start)


def test_router_failure_risk_fires_on_rising_cpu():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=_cpu_history([50.0, 55.0, 60.0, 65.0], start=start),
        memory_history=_cpu_history([40.0, 40.0, 40.0, 40.0], start=start),
        unhealthy_snapshot_count=0,
        total_snapshot_count=4,
        alert_count=0,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert isinstance(result, RouterFailureRiskResult)
    assert result.at_risk is True
    names = [s.name for s in result.signals]
    assert names == ["rising_cpu_usage"]


def test_router_failure_risk_no_fire_when_everything_flat_and_healthy():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=_cpu_history([40.0, 40.0, 40.0], start=start),
        memory_history=_cpu_history([30.0, 30.0, 30.0], start=start),
        unhealthy_snapshot_count=0,
        total_snapshot_count=3,
        alert_count=0,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert result.at_risk is False
    assert result.signals == []


def test_router_failure_risk_fires_on_degrading_health_status_ratio():
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=[],
        memory_history=[],
        unhealthy_snapshot_count=3,
        total_snapshot_count=4,
        alert_count=0,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert result.at_risk is True
    assert [s.name for s in result.signals] == ["degrading_health_status"]


def test_router_failure_risk_no_fire_below_unhealthy_ratio_threshold():
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=[],
        memory_history=[],
        unhealthy_snapshot_count=1,
        total_snapshot_count=10,
        alert_count=0,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert result.at_risk is False


def test_router_failure_risk_fires_on_repeated_alerts():
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=[],
        memory_history=[],
        unhealthy_snapshot_count=0,
        total_snapshot_count=0,
        alert_count=3,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert result.at_risk is True
    assert [s.name for s in result.signals] == ["repeated_alerts"]


def test_router_failure_risk_no_fire_below_alert_count_threshold():
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=[],
        memory_history=[],
        unhealthy_snapshot_count=0,
        total_snapshot_count=0,
        alert_count=1,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert result.at_risk is False


def test_router_failure_risk_no_cpu_signal_below_min_history_points():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    result = assess_router_failure_risk(
        router_id=_ROUTER_ID,
        router_name="R1",
        cpu_history=_cpu_history([50.0, 90.0], start=start),  # only 2 points
        memory_history=[],
        unhealthy_snapshot_count=0,
        total_snapshot_count=2,
        alert_count=0,
        cpu_rising_slope_threshold=1.0,
        memory_rising_slope_threshold=1.0,
        unhealthy_ratio_threshold=0.3,
        alert_count_threshold=2,
        min_history_points=3,
    )
    assert result.at_risk is False


# ============================================================================
# trends.py -- the shared Trend Engine helpers
# ============================================================================


@dataclass
class _FakeSnapshot:
    period_start: datetime
    metrics: dict
    period_end: datetime | None = None
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None


def test_extract_metric_series_sorts_and_defaults_missing_to_zero():
    d0 = datetime(2026, 1, 1, tzinfo=UTC)
    d1 = datetime(2026, 1, 2, tzinfo=UTC)
    snapshots = [
        _FakeSnapshot(period_start=d1, metrics={"x": 20}),
        _FakeSnapshot(period_start=d0, metrics={}),  # missing key -> 0.0
    ]
    series = extract_metric_series(snapshots, "x")
    assert [p.timestamp for p in series] == [d0, d1]
    assert [p.value for p in series] == [0.0, 20.0]


def test_growth_point_response_delegates_to_compute_growth():
    response = growth_point_response("metric", 20.0, 10.0)
    assert response.direction == "increasing"
    assert response.delta_percent == pytest.approx(100.0)


def test_build_growth_trend_day_over_day_series():
    d0 = datetime(2026, 1, 1, tzinfo=UTC)
    d1 = d0 + timedelta(days=1)
    d2 = d0 + timedelta(days=2)
    snapshots = [
        _FakeSnapshot(period_start=d0, metrics={"total_bandwidth_bytes": 100}),
        _FakeSnapshot(period_start=d1, metrics={"total_bandwidth_bytes": 150}),
        _FakeSnapshot(period_start=d2, metrics={"total_bandwidth_bytes": 90}),
    ]
    trend = build_growth_trend(snapshots, "total_bandwidth_bytes")
    assert len(trend) == 3
    assert trend[0].previous_value is None
    assert trend[1].direction == "increasing"
    assert trend[2].direction == "decreasing"


def test_count_trailing_consecutive_increases():
    assert count_trailing_consecutive_increases([40, 45, 50, 62]) == 3
    assert count_trailing_consecutive_increases([40, 45, 42, 50]) == 1
    assert count_trailing_consecutive_increases([50, 40, 30]) == 0
    assert count_trailing_consecutive_increases([]) == 0
    assert count_trailing_consecutive_increases([5]) == 0


class _FakeSnapshotRepository:
    """Satisfies ``trends.SnapshotHistoryLookupProtocol``."""

    def __init__(self, *, latest, previous_rows) -> None:
        self._latest = latest
        self._previous_rows = previous_rows

    async def get_latest_snapshot(self, *, organization_id, location_id, snapshot_type):
        return self._latest

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
        return self._previous_rows, None


async def test_compute_snapshot_metric_growth_real_current_vs_previous():
    now = datetime(2026, 1, 10, tzinfo=UTC)
    latest = _FakeSnapshot(period_start=now, metrics={"organization_count_total": 12})
    previous = _FakeSnapshot(
        period_start=now - timedelta(days=8),
        metrics={"organization_count_total": 10},
    )
    repo = _FakeSnapshotRepository(latest=latest, previous_rows=[previous])
    growth = await compute_snapshot_metric_growth(
        repo,
        organization_id=None,
        location_id=None,
        snapshot_type="platform_daily_summary",
        metric_key="organization_count_total",
        lookback_days=7,
        now=now,
    )
    assert growth.current_value == pytest.approx(12.0)
    assert growth.previous_value == pytest.approx(10.0)
    assert growth.direction == "increasing"


async def test_compute_snapshot_metric_growth_no_history_is_unknown():
    now = datetime(2026, 1, 10, tzinfo=UTC)
    repo = _FakeSnapshotRepository(latest=None, previous_rows=[])
    growth = await compute_snapshot_metric_growth(
        repo,
        organization_id=None,
        location_id=None,
        snapshot_type="platform_daily_summary",
        metric_key="organization_count_total",
        lookback_days=7,
        now=now,
    )
    assert growth.current_value == pytest.approx(0.0)
    assert growth.previous_value is None
    assert growth.direction == "unknown"


# ============================================================================
# insights.py -- every rule, fire AND no-fire
# ============================================================================


def test_rule_customer_growth_fires_info_on_significant_increase():
    insight = rule_customer_growth(
        delta_percent=15.0, direction="increasing", significant_percent_threshold=10.0
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.INFO
    assert "increased 15.0%" in insight.message


def test_rule_customer_growth_fires_warning_on_significant_decrease():
    insight = rule_customer_growth(
        delta_percent=-20.0, direction="decreasing", significant_percent_threshold=10.0
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.WARNING
    assert "decreased 20.0%" in insight.message


def test_rule_customer_growth_no_fire_below_threshold():
    assert (
        rule_customer_growth(
            delta_percent=5.0,
            direction="increasing",
            significant_percent_threshold=10.0,
        )
        is None
    )


def test_rule_customer_growth_no_fire_when_delta_percent_none():
    assert (
        rule_customer_growth(
            delta_percent=None, direction="unknown", significant_percent_threshold=10.0
        )
        is None
    )


def test_rule_guest_growth_fires_and_no_fires():
    insight = rule_guest_growth(
        delta_percent=18.0, direction="increasing", significant_percent_threshold=15.0
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.INFO
    assert (
        rule_guest_growth(
            delta_percent=5.0,
            direction="increasing",
            significant_percent_threshold=15.0,
        )
        is None
    )


def test_rule_plan_distribution_coverage_fires_when_sparse():
    insight = rule_plan_distribution_coverage(
        populated_count=10, total_count=100, min_coverage_percent_threshold=50.0
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.INFO
    assert "10%" in insight.message


def test_rule_plan_distribution_coverage_no_fire_when_well_covered():
    assert (
        rule_plan_distribution_coverage(
            populated_count=60, total_count=100, min_coverage_percent_threshold=50.0
        )
        is None
    )


def test_rule_plan_distribution_coverage_no_fire_when_zero_organizations():
    assert (
        rule_plan_distribution_coverage(
            populated_count=0, total_count=0, min_coverage_percent_threshold=50.0
        )
        is None
    )


def test_rule_offline_routers_fires_warning():
    insight = rule_offline_routers(
        organization_id=uuid.uuid4(),
        organization_name="Acme",
        offline_count=1,
        hours_threshold=24,
        count_threshold=1,
        critical_count_threshold=3,
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.WARNING


def test_rule_offline_routers_escalates_to_critical():
    insight = rule_offline_routers(
        organization_id=uuid.uuid4(),
        organization_name="Acme",
        offline_count=5,
        hours_threshold=24,
        count_threshold=1,
        critical_count_threshold=3,
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.CRITICAL


def test_rule_offline_routers_no_fire_below_count_threshold():
    assert (
        rule_offline_routers(
            organization_id=uuid.uuid4(),
            organization_name="Acme",
            offline_count=0,
            hours_threshold=24,
            count_threshold=1,
            critical_count_threshold=3,
        )
        is None
    )


def test_rule_location_guest_volume_drop_fires():
    insight = rule_location_guest_volume_drop(
        location_id=uuid.uuid4(),
        location_name="Lobby",
        delta_percent=-25.0,
        drop_percent_threshold=20.0,
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.WARNING
    assert "25.0%" in insight.message


def test_rule_location_guest_volume_drop_no_fire_below_threshold():
    assert (
        rule_location_guest_volume_drop(
            location_id=uuid.uuid4(),
            location_name="Lobby",
            delta_percent=-10.0,
            drop_percent_threshold=20.0,
        )
        is None
    )


def test_rule_location_guest_volume_drop_no_fire_when_none():
    assert (
        rule_location_guest_volume_drop(
            location_id=uuid.uuid4(),
            location_name="Lobby",
            delta_percent=None,
            drop_percent_threshold=20.0,
        )
        is None
    )


def test_rule_rising_router_cpu_fires():
    insight = rule_rising_router_cpu(
        router_id=uuid.uuid4(),
        router_name="R1",
        consecutive_rises=3,
        consecutive_threshold=3,
        first_value=40.0,
        last_value=62.0,
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.WARNING
    assert "3 consecutive" in insight.message


def test_rule_rising_router_cpu_no_fire_below_threshold():
    assert (
        rule_rising_router_cpu(
            router_id=uuid.uuid4(),
            router_name="R1",
            consecutive_rises=2,
            consecutive_threshold=3,
            first_value=40.0,
            last_value=50.0,
        )
        is None
    )


def test_rule_persistent_critical_alerts_fires():
    insight = rule_persistent_critical_alerts(
        organization_id=uuid.uuid4(),
        organization_name="Acme",
        count=2,
        count_threshold=2,
        age_hours_threshold=24,
    )
    assert insight is not None
    assert insight.severity == InsightSeverity.CRITICAL


def test_rule_persistent_critical_alerts_no_fire_below_threshold():
    assert (
        rule_persistent_critical_alerts(
            organization_id=uuid.uuid4(),
            organization_name="Acme",
            count=1,
            count_threshold=2,
            age_hours_threshold=24,
        )
        is None
    )


# ============================================================================
# Shared fakes for the service-layer tests below (Business/Forecast/Insight)
# ============================================================================


@dataclass
class _FakeRole:
    is_active: bool = True
    is_deleted: bool = False


@dataclass
class _FakeAssignment:
    scope_type: str
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    msp_id: uuid.UUID | None = None
    role: _FakeRole = field(default_factory=_FakeRole)


class _FakeRoleResolver:
    def __init__(self, assignments: list[_FakeAssignment]) -> None:
        self._assignments = assignments

    async def get_active_assignments(self, user_id, *, now=None):
        from app.domains.rbac.authorization import ActiveRoleAssignment

        return [
            ActiveRoleAssignment(assignment=a, role=a.role) for a in self._assignments
        ]


class _FakeOrganizationLookup:
    def __init__(self, organizations=None, children=None) -> None:
        self._organizations = organizations or {}
        self._children = children or {}

    async def get_organization(self, organization_id, *, include_deleted=False):
        return self._organizations[organization_id]

    async def list_children(self, organization_id):
        return self._children.get(organization_id, [])


class _FakeLocationLookup:
    def __init__(self, locations=None) -> None:
        self._locations = locations or {}

    async def get_location(
        self, location_id, *, requesting_organization_id=None, include_deleted=False
    ):
        return self._locations[location_id]


def _global_scope_resolver() -> DashboardScopeResolver:
    return DashboardScopeResolver(
        _FakeRoleResolver([_FakeAssignment(scope_type=ScopeType.GLOBAL.value)]),
        _FakeOrganizationLookup(),
        _FakeLocationLookup(),
    )


@dataclass
class _FakeOrganization:
    id: uuid.UUID
    org_type: str = "standard"
    name: str = "Fake Org"

    def is_msp(self) -> bool:
        return False


def _org_scope_resolver(organization_id: uuid.UUID) -> DashboardScopeResolver:
    return DashboardScopeResolver(
        _FakeRoleResolver(
            [
                _FakeAssignment(
                    scope_type=ScopeType.ORGANIZATION.value,
                    organization_id=organization_id,
                )
            ]
        ),
        _FakeOrganizationLookup(
            {organization_id: _FakeOrganization(id=organization_id)}
        ),
        _FakeLocationLookup(),
    )


def _no_scope_resolver() -> DashboardScopeResolver:
    return DashboardScopeResolver(
        _FakeRoleResolver([]), _FakeOrganizationLookup(), _FakeLocationLookup()
    )


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def set(self, key, value, *, nx=False, ex=None):
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True


class _FakePart4Repository:
    """Stand-in for ``AnalyticsRepositoryProtocol`` covering only the BE-012
    Part 4 surface ``BusinessAnalyticsService``/``ForecastService``/
    ``InsightService`` need."""

    def __init__(self, **overrides) -> None:
        self.latest_snapshot = overrides.get("latest_snapshot")
        self.list_snapshots_result = overrides.get("list_snapshots_result", [])
        self.subscription_tier_rows = overrides.get("subscription_tier_rows", [])
        self.routers = overrides.get("routers", [])
        self.all_routers = overrides.get("all_routers", [])
        self.health_history = overrides.get("health_history", {})
        self.alert_counts_by_router = overrides.get("alert_counts_by_router", {})
        self.persistent_critical_alert_counts = overrides.get(
            "persistent_critical_alert_counts", []
        )
        self.organization_names = overrides.get("organization_names", {})
        self.location_names = overrides.get("location_names", {})

    async def get_latest_snapshot(self, *, organization_id, location_id, snapshot_type):
        return self.latest_snapshot

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
        return self.list_snapshots_result, None

    async def count_organizations_by_subscription_tier(self):
        return self.subscription_tier_rows

    async def list_routers_for_scope(self, *, organization_id, location_id=None):
        return self.routers

    async def get_router_health_snapshot_history(self, router_ids, *, start, end):
        return {
            rid: rows for rid, rows in self.health_history.items() if rid in router_ids
        }

    async def get_alert_counts_by_router(self, router_ids, *, since):
        return {
            rid: count
            for rid, count in self.alert_counts_by_router.items()
            if rid in router_ids
        }

    async def list_all_routers_with_organization(self):
        return self.all_routers

    async def get_persistent_critical_alert_counts_by_organization(self, *, older_than):
        return self.persistent_critical_alert_counts

    async def get_organization_names(self, organization_ids):
        return {
            oid: name
            for oid, name in self.organization_names.items()
            if oid in organization_ids
        }

    async def get_location_names(self, location_ids):
        return {
            lid: name
            for lid, name in self.location_names.items()
            if lid in location_ids
        }


# ============================================================================
# BusinessAnalyticsService -- Customer Growth/Plan Distribution real-query
# correctness, honest placeholders, tenant isolation
# ============================================================================


async def test_business_analytics_customer_growth_and_plan_distribution_real():
    now = datetime(2026, 1, 10, tzinfo=UTC)
    latest = _FakeSnapshot(period_start=now, metrics={"organization_count_total": 22})
    previous = _FakeSnapshot(
        period_start=now - timedelta(days=8), metrics={"organization_count_total": 20}
    )
    repository = _FakePart4Repository(
        latest_snapshot=latest,
        list_snapshots_result=[previous],
        subscription_tier_rows=[("starter", 3), (None, 7), ("enterprise", 1)],
    )
    service = BusinessAnalyticsService(
        repository, _global_scope_resolver(), _FakeRedis()
    )

    result = await service.get_business_analytics(uuid.uuid4())

    assert result.customer_growth.current_value == pytest.approx(22.0)
    assert result.customer_growth.previous_value == pytest.approx(20.0)
    assert result.customer_growth.direction == "increasing"

    assert isinstance(result.plan_distribution, PlanDistributionResponse)
    assert result.plan_distribution.total_organizations == 11
    assert result.plan_distribution.populated_organizations == 4
    assert result.plan_distribution.unset_organizations == 7
    tiers = {
        item.tier: item.organization_count for item in result.plan_distribution.by_tier
    }
    assert tiers == {"starter": 3, "enterprise": 1, "unset": 7}


async def test_business_analytics_honest_placeholders():
    repository = _FakePart4Repository()
    service = BusinessAnalyticsService(
        repository, _global_scope_resolver(), _FakeRedis()
    )
    result = await service.get_business_analytics(uuid.uuid4())

    assert result.revenue_trends.available is False
    assert result.subscription_trends.available is False
    assert result.churn_rate.available is False
    assert result.churn_rate.churn_rate_percent is None
    assert result.renewal_rate.available is False
    assert result.license_utilization.available is False


async def test_business_analytics_rejects_non_global_caller():
    repository = _FakePart4Repository()
    org_id = uuid.uuid4()
    service = BusinessAnalyticsService(
        repository, _org_scope_resolver(org_id), _FakeRedis()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_business_analytics(uuid.uuid4())


# ============================================================================
# ForecastService -- linear forecasts, capacity threshold-crossing, router
# failure risk, tenant isolation
# ============================================================================


def _forecast_settings(**overrides) -> Settings:
    return Settings(**overrides)


async def test_forecast_bandwidth_forecast_projects_from_real_snapshot_history():
    org_id = uuid.uuid4()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    snapshots = [
        _FakeSnapshot(
            period_start=start + timedelta(days=i),
            metrics={"total_bandwidth_bytes": 1000 * (i + 1)},
        )
        for i in range(4)
    ]
    repository = _FakePart4Repository(list_snapshots_result=snapshots)
    service = ForecastService(
        repository,
        _org_scope_resolver(org_id),
        _FakeRedis(),
        _forecast_settings(analytics_forecast_min_history_points=3),
    )
    result = await service.get_bandwidth_forecast(
        uuid.uuid4(), org_id, location_id=None, forecast_days=2
    )
    assert result.available is True
    assert result.fit is not None
    assert result.fit.slope_per_day == pytest.approx(1000.0)
    assert len(result.projected_points) == 2


async def test_forecast_unavailable_with_too_little_history():
    org_id = uuid.uuid4()
    repository = _FakePart4Repository(list_snapshots_result=[])
    service = ForecastService(
        repository, _org_scope_resolver(org_id), _FakeRedis(), _forecast_settings()
    )
    result = await service.get_guest_growth_forecast(
        uuid.uuid4(), org_id, location_id=None, forecast_days=None
    )
    assert result.available is False


async def test_forecast_capacity_prediction_threshold_crossing():
    org_id = uuid.uuid4()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    snapshots = [
        _FakeSnapshot(
            period_start=start + timedelta(days=i),
            metrics={"router_count_total": 10 + i},
        )
        for i in range(4)
    ]
    repository = _FakePart4Repository(list_snapshots_result=snapshots)
    service = ForecastService(
        repository,
        _org_scope_resolver(org_id),
        _FakeRedis(),
        _forecast_settings(
            analytics_forecast_min_history_points=3,
            analytics_forecast_capacity_router_count_threshold=20,
        ),
    )
    result = await service.get_capacity_forecast(uuid.uuid4(), org_id, location_id=None)
    assert result.threshold_crossing.available is True
    assert result.threshold_crossing.days_until_crossing == 7
    assert result.threshold_crossing.threshold == pytest.approx(20.0)


async def test_forecast_router_failure_risk_composes_repository_history():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime(2026, 1, 10, tzinfo=UTC)
    from app.domains.analytics.repository import RouterSummaryRow

    repository = _FakePart4Repository(
        routers=[
            RouterSummaryRow(
                router_id=router_id,
                router_name="R1",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            )
        ],
        health_history={
            router_id: [
                RouterHealthHistoryRow(
                    recorded_at=now - timedelta(days=3 - i),
                    cpu_usage_percent=50.0 + i * 10,
                    memory_usage_percent=30.0,
                    health_status="healthy",
                )
                for i in range(4)
            ]
        },
        alert_counts_by_router={router_id: 0},
    )
    service = ForecastService(
        repository,
        _org_scope_resolver(org_id),
        _FakeRedis(),
        _forecast_settings(
            analytics_forecast_min_history_points=3,
            analytics_forecast_router_cpu_rising_slope_threshold=1.0,
        ),
    )
    result = await service.get_router_failure_risk(
        uuid.uuid4(), org_id, location_id=None
    )
    assert len(result.routers) == 1
    assert result.routers[0].at_risk is True
    assert any(s.name == "rising_cpu_usage" for s in result.routers[0].signals)


async def test_forecast_rejects_out_of_scope_organization():
    org_id = uuid.uuid4()
    repository = _FakePart4Repository()
    service = ForecastService(
        repository, _no_scope_resolver(), _FakeRedis(), _forecast_settings()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_bandwidth_forecast(
            uuid.uuid4(), org_id, location_id=None, forecast_days=None
        )


# ============================================================================
# InsightService -- Business Insights + Operational Recommendations
# composition, tenant isolation
# ============================================================================


async def test_insight_service_business_insights_composes_real_data():
    now = datetime(2026, 1, 10, tzinfo=UTC)
    latest = _FakeSnapshot(
        period_start=now,
        metrics={"organization_count_total": 20, "guest_count_unique_today": 200},
    )
    previous = _FakeSnapshot(
        period_start=now - timedelta(days=8),
        metrics={"organization_count_total": 10, "guest_count_unique_today": 100},
    )
    repository = _FakePart4Repository(
        latest_snapshot=latest,
        list_snapshots_result=[previous],
        subscription_tier_rows=[(None, 100)],
    )
    service = InsightService(
        repository, _global_scope_resolver(), _FakeRedis(), Settings()
    )
    result = await service.get_business_insights(uuid.uuid4())
    rules_fired = {item.rule for item in result.insights}
    assert "customer_growth" in rules_fired
    assert "guest_growth" in rules_fired
    assert "plan_distribution_coverage" in rules_fired


async def test_insight_service_operational_recommendations_offline_routers():
    org_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime(2026, 1, 10, tzinfo=UTC)
    repository = _FakePart4Repository(
        all_routers=[
            RouterStatusRow(
                organization_id=org_id,
                organization_name="Acme",
                router_id=router_id,
                router_name="R1",
                location_id=uuid.uuid4(),
                status=RouterStatus.OFFLINE.value,
                last_seen_at=now - timedelta(hours=48),
            )
        ]
    )
    service = InsightService(
        repository,
        _global_scope_resolver(),
        _FakeRedis(),
        Settings(
            analytics_insight_offline_router_hours_threshold=24,
            analytics_insight_offline_router_count_threshold=1,
        ),
    )
    result = await service.get_operational_recommendations(uuid.uuid4())
    assert any(item.rule == "offline_routers" for item in result.recommendations)


async def test_insight_service_operational_recommendations_persistent_critical_alerts():
    org_id = uuid.uuid4()
    repository = _FakePart4Repository(
        persistent_critical_alert_counts=[(org_id, 3)],
        organization_names={org_id: "Acme"},
    )
    service = InsightService(
        repository,
        _global_scope_resolver(),
        _FakeRedis(),
        Settings(analytics_insight_critical_alert_count_threshold=2),
    )
    result = await service.get_operational_recommendations(uuid.uuid4())
    assert any(
        item.rule == "persistent_critical_alerts" for item in result.recommendations
    )


async def test_insight_service_operational_recommendations_no_fire_when_all_healthy():
    repository = _FakePart4Repository()
    service = InsightService(
        repository, _global_scope_resolver(), _FakeRedis(), Settings()
    )
    result = await service.get_operational_recommendations(uuid.uuid4())
    assert result.recommendations == []


async def test_insight_service_rejects_non_global_caller():
    org_id = uuid.uuid4()
    repository = _FakePart4Repository()
    service = InsightService(
        repository, _org_scope_resolver(org_id), _FakeRedis(), Settings()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_business_insights(uuid.uuid4())
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_operational_recommendations(uuid.uuid4())


# ============================================================================
# Route registration / RBAC scope wiring
# ============================================================================


def _permission_key_and_scope_for_route(route) -> tuple[str | None, str | None]:
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            key_index = freevars.index("permission_key")
            permission_key = call.__closure__[key_index].cell_contents
            scope_value = None
            if "scope" in freevars:
                scope_index = freevars.index("scope")
                scope = call.__closure__[scope_index].cell_contents
                scope_value = scope.value if scope is not None else None
            return permission_key, scope_value
    return None, None


@pytest.fixture(scope="module")
def part4_routes_by_path():
    from app.main import create_app

    app = create_app()
    routes: dict[str, object] = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        if path and path.startswith("/api/v1/analytics/"):
            routes[path] = route
    return routes


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/analytics/business",
        "/api/v1/analytics/insights/business",
        "/api/v1/analytics/insights/operational",
    ],
)
def test_global_scoped_endpoints_require_analytics_read_at_global_scope(
    part4_routes_by_path, path
):
    route = part4_routes_by_path[path]
    permission_key, scope = _permission_key_and_scope_for_route(route)
    assert permission_key == "analytics.read"
    assert scope == "global"


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/analytics/forecast/bandwidth",
        "/api/v1/analytics/forecast/capacity",
        "/api/v1/analytics/forecast/router-failure-risk",
        "/api/v1/analytics/forecast/guest-growth",
        "/api/v1/analytics/forecast/network-load",
    ],
)
def test_forecast_endpoints_require_analytics_read_at_organization_scope(
    part4_routes_by_path, path
):
    route = part4_routes_by_path[path]
    permission_key, scope = _permission_key_and_scope_for_route(route)
    assert permission_key == "analytics.read"
    assert scope == "organization"


def test_app_boots_with_part4_routes_registered_and_no_route_conflicts():
    from app.main import create_app

    app = create_app()
    paths = {getattr(r, "path", None) for r in app.routes}
    for expected in [
        "/api/v1/analytics/business",
        "/api/v1/analytics/forecast/bandwidth",
        "/api/v1/analytics/forecast/capacity",
        "/api/v1/analytics/forecast/router-failure-risk",
        "/api/v1/analytics/forecast/guest-growth",
        "/api/v1/analytics/forecast/network-load",
        "/api/v1/analytics/insights/business",
        "/api/v1/analytics/insights/operational",
    ]:
        assert expected in paths

    seen: set[tuple[str, frozenset[str]]] = set()
    for route in app.routes:
        route_path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if route_path is None or methods is None:
            continue
        key = (route_path, frozenset(methods))
        assert key not in seen, f"duplicate route registered: {key}"
        seen.add(key)

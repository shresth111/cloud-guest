"""Unit tests for BE-012 Part 2 (Super Admin + Organization + Location
Dashboards): peak-concurrent-sessions correctness against a hand-constructed
overlapping-intervals fixture, the Organization Health Score formula against
known inputs, MSP-child rollup, weekly/monthly aggregation-from-daily-
snapshots correctness, peak hour/day correctness, the device/browser/OS
real-capture-and-parse path, scope-rejection (an org admin cannot view
another org's dashboard, a location admin cannot view a location outside
their scope), and revenue/ARR/MRR honestly returning unavailable.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_analytics.py``'s own module docstring) -- every fake below
is a small, hand-rolled stand-in for the narrow protocol it satisfies, no
live Postgres/Redis anywhere in this test suite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.analytics.constants import AnalyticsSnapshotType
from app.domains.analytics.dashboard_aggregation import (
    TrendDirection,
    average_metric_across_snapshots,
    compute_growth,
    growth_direction_to_health_direction,
    sum_metric_across_snapshots,
)
from app.domains.analytics.dashboard_audit import DashboardAuditThrottle
from app.domains.analytics.dashboard_schemas import RevenueMetricsResponse
from app.domains.analytics.dashboard_scope import (
    DashboardScope,
    DashboardScopeLevel,
    DashboardScopeResolver,
)
from app.domains.analytics.dashboard_service import DashboardService
from app.domains.analytics.exceptions import DashboardScopeForbiddenError
from app.domains.analytics.health_score import (
    GrowthDirection,
    compute_health_score,
)
from app.domains.analytics.models import AnalyticsSnapshot
from app.domains.analytics.peak_concurrency import compute_peak_concurrent_sessions
from app.domains.analytics.repository import OtpStatsRow, UserAgentBreakdown
from app.domains.rbac.context import GrantScope
from app.domains.rbac.enums import ScopeType

# ============================================================================
# peak_concurrency.compute_peak_concurrent_sessions -- hand-constructed
# overlapping-intervals fixtures
# ============================================================================


def _dt(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 1, 1, hour, minute, tzinfo=UTC)


def test_peak_concurrency_no_overlap_is_one():
    intervals = [
        (_dt(9), _dt(10)),
        (_dt(10), _dt(11)),
        (_dt(11), _dt(12)),
    ]
    peak = compute_peak_concurrent_sessions(
        intervals, window_start=_dt(0), window_end=_dt(23)
    )
    assert peak == 1


def test_peak_concurrency_three_way_overlap():
    """Session A: 09:00-11:00, B: 10:00-12:00, C: 10:30-10:45 -- all three
    overlap during [10:30, 10:45), so the true peak is 3."""
    intervals = [
        (_dt(9), _dt(11)),
        (_dt(10), _dt(12)),
        (_dt(10, 30), _dt(10, 45)),
    ]
    peak = compute_peak_concurrent_sessions(
        intervals, window_start=_dt(0), window_end=_dt(23)
    )
    assert peak == 3


def test_peak_concurrency_half_open_interval_convention():
    """A session ending exactly when another starts must not count as
    briefly overlapping (half-open ``[start, end)`` convention)."""
    intervals = [(_dt(9), _dt(10)), (_dt(10), _dt(11))]
    peak = compute_peak_concurrent_sessions(
        intervals, window_start=_dt(0), window_end=_dt(23)
    )
    assert peak == 1


def test_peak_concurrency_active_session_treated_as_alive_through_window_end():
    intervals = [(_dt(9), None), (_dt(9, 30), _dt(10))]
    peak = compute_peak_concurrent_sessions(
        intervals, window_start=_dt(0), window_end=_dt(23)
    )
    assert peak == 2


def test_peak_concurrency_clips_to_window():
    """An interval that starts before the window and ends after it is
    clipped, not dropped -- it still counts across the entire window."""
    intervals = [(_dt(0), _dt(23, 59)), (_dt(5), _dt(6))]
    peak = compute_peak_concurrent_sessions(
        intervals, window_start=_dt(1), window_end=_dt(20)
    )
    assert peak == 2


def test_peak_concurrency_empty_intervals_is_zero():
    assert (
        compute_peak_concurrent_sessions([], window_start=_dt(0), window_end=_dt(23))
        == 0
    )


# ============================================================================
# health_score.compute_health_score -- known inputs
# ============================================================================


def test_health_score_all_healthy_no_alerts_growing():
    result = compute_health_score(
        router_online_count=10,
        router_total_count=10,
        open_alert_counts_by_severity={},
        growth_direction=GrowthDirection.GROWING,
    )
    # 0.50*100 + 0.30*100 + 0.20*100 = 100
    assert result.score == 100
    assert result.router_health_component == 100.0
    assert result.alert_health_component == 100.0
    assert result.growth_health_component == 100.0


def test_health_score_exact_weighted_formula():
    # router: 5/10 online = 50.0 -> 0.50*50 = 25.0
    # alerts: 1 critical (25) + 1 warning (10) = 35 penalty -> component 65.0
    #         -> 0.30*65 = 19.5
    # growth: declining -> 40.0 -> 0.20*40 = 8.0
    # total = 25.0 + 19.5 + 8.0 = 52.5 -> round -> 52 (banker's rounding on .5)
    result = compute_health_score(
        router_online_count=5,
        router_total_count=10,
        open_alert_counts_by_severity={"critical": 1, "warning": 1},
        growth_direction=GrowthDirection.DECLINING,
    )
    assert result.router_health_component == 50.0
    assert result.alert_health_component == 65.0
    assert result.growth_health_component == 40.0
    assert result.open_alert_penalty == 35.0
    assert result.score == round(25.0 + 19.5 + 8.0)


def test_health_score_zero_routers_scores_full_router_component():
    result = compute_health_score(
        router_online_count=0,
        router_total_count=0,
        open_alert_counts_by_severity={},
        growth_direction=GrowthDirection.FLAT,
    )
    assert result.router_health_component == 100.0


def test_health_score_alert_penalty_caps_at_100():
    result = compute_health_score(
        router_online_count=10,
        router_total_count=10,
        open_alert_counts_by_severity={"critical": 10},
        growth_direction=GrowthDirection.GROWING,
    )
    assert result.open_alert_penalty == 100.0
    assert result.alert_health_component == 0.0


def test_health_score_clamped_between_0_and_100():
    result = compute_health_score(
        router_online_count=0,
        router_total_count=10,
        open_alert_counts_by_severity={"critical": 100},
        growth_direction=GrowthDirection.DECLINING,
    )
    assert 0 <= result.score <= 100


# ============================================================================
# dashboard_aggregation -- growth points, snapshot summation
# ============================================================================


def test_compute_growth_increasing():
    point = compute_growth(metric="guests", current=120.0, previous=100.0)
    assert point.delta == 20.0
    assert point.delta_percent == 20.0
    assert point.direction == TrendDirection.INCREASING


def test_compute_growth_no_previous_is_unknown():
    point = compute_growth(metric="guests", current=10.0, previous=None)
    assert point.previous_value is None
    assert point.delta is None
    assert point.delta_percent is None
    assert point.direction == TrendDirection.UNKNOWN


def test_compute_growth_previous_zero_never_divides_by_zero():
    point = compute_growth(metric="guests", current=5.0, previous=0.0)
    assert point.delta == 5.0
    assert point.delta_percent is None


def test_compute_growth_flat():
    point = compute_growth(metric="guests", current=10.0, previous=10.0)
    assert point.direction == TrendDirection.FLAT
    assert point.delta == 0.0


def test_growth_direction_to_health_direction_mapping():
    assert (
        growth_direction_to_health_direction(TrendDirection.INCREASING)
        == GrowthDirection.GROWING
    )
    assert (
        growth_direction_to_health_direction(TrendDirection.DECREASING)
        == GrowthDirection.DECLINING
    )
    assert (
        growth_direction_to_health_direction(TrendDirection.FLAT)
        == GrowthDirection.FLAT
    )
    assert (
        growth_direction_to_health_direction(TrendDirection.UNKNOWN)
        == GrowthDirection.UNKNOWN
    )


def test_sum_metric_across_snapshots():
    snapshots = [{"session_count_total": 10}, {"session_count_total": 5}, {}]
    assert sum_metric_across_snapshots(snapshots, "session_count_total") == 15


def test_average_metric_across_snapshots():
    snapshots = [
        {"average_session_duration_seconds": 100.0},
        {"average_session_duration_seconds": 200.0},
        {"average_session_duration_seconds": None},
    ]
    assert (
        average_metric_across_snapshots(snapshots, "average_session_duration_seconds")
        == 150.0
    )


def test_average_metric_across_snapshots_none_when_no_data():
    assert average_metric_across_snapshots([{}], "missing_key") is None


# ============================================================================
# DashboardScope -- allows_*/require_* real, independent checks
# ============================================================================


def test_dashboard_scope_global_allows_everything():
    scope = DashboardScope(level=DashboardScopeLevel.GLOBAL)
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    assert scope.allows_organization(org_id)
    assert scope.allows_location(loc_id, org_id)
    scope.require_global()
    scope.require_organization(org_id)
    scope.require_location(loc_id, org_id)


def test_dashboard_scope_organization_level_covers_its_locations():
    org_id = uuid.uuid4()
    other_org_id = uuid.uuid4()
    scope = DashboardScope(
        level=DashboardScopeLevel.ORGANIZATION, organization_ids=frozenset({org_id})
    )
    assert scope.allows_organization(org_id)
    assert not scope.allows_organization(other_org_id)
    assert scope.allows_location(uuid.uuid4(), org_id)
    assert not scope.allows_location(uuid.uuid4(), other_org_id)
    with pytest.raises(DashboardScopeForbiddenError):
        scope.require_organization(other_org_id)
    with pytest.raises(DashboardScopeForbiddenError):
        scope.require_global()


def test_dashboard_scope_location_level_cannot_satisfy_organization_check():
    """A location-scoped grant can never satisfy a broader organization-level
    check -- the same asymmetry RBAC's own ScopeResolver enforces."""
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    other_loc_id = uuid.uuid4()
    scope = DashboardScope(
        level=DashboardScopeLevel.LOCATION, location_ids=frozenset({loc_id})
    )
    assert scope.allows_location(loc_id, org_id)
    assert not scope.allows_location(other_loc_id, org_id)
    assert not scope.allows_organization(org_id)
    with pytest.raises(DashboardScopeForbiddenError):
        scope.require_organization(org_id)
    with pytest.raises(DashboardScopeForbiddenError):
        scope.require_location(other_loc_id, org_id)


# ============================================================================
# DashboardScopeResolver -- composes RoleResolver + Organization/Location
# lookups
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


@dataclass
class _FakeOrganization:
    id: uuid.UUID
    org_type: str = "standard"
    name: str = "Fake Org"

    def is_msp(self) -> bool:
        return self.org_type == "msp"


class _FakeOrganizationLookup:
    def __init__(
        self,
        organizations: dict[uuid.UUID, _FakeOrganization],
        children: dict[uuid.UUID, list[_FakeOrganization]] | None = None,
    ) -> None:
        self._organizations = organizations
        self._children = children or {}

    async def get_organization(self, organization_id, *, include_deleted=False):
        return self._organizations[organization_id]

    async def list_children(self, organization_id):
        return self._children.get(organization_id, [])


@dataclass
class _FakeLocation:
    id: uuid.UUID
    organization_id: uuid.UUID


class _FakeLocationLookup:
    def __init__(self, locations: dict[uuid.UUID, _FakeLocation]) -> None:
        self._locations = locations

    async def get_location(
        self, location_id, *, requesting_organization_id=None, include_deleted=False
    ):
        return self._locations[location_id]


async def test_scope_resolver_global_role_short_circuits():
    assignments = [_FakeAssignment(scope_type=ScopeType.GLOBAL.value)]
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(assignments),
        _FakeOrganizationLookup({}),
        _FakeLocationLookup({}),
    )
    scope = await resolver.resolve(uuid.uuid4())
    assert scope.level == DashboardScopeLevel.GLOBAL


async def test_scope_resolver_msp_organization_expands_children():
    msp_id = uuid.uuid4()
    child_a = uuid.uuid4()
    child_b = uuid.uuid4()
    assignments = [
        _FakeAssignment(scope_type=ScopeType.ORGANIZATION.value, organization_id=msp_id)
    ]
    organizations = {msp_id: _FakeOrganization(id=msp_id, org_type="msp")}
    children = {
        msp_id: [
            _FakeOrganization(id=child_a),
            _FakeOrganization(id=child_b),
        ]
    }
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(assignments),
        _FakeOrganizationLookup(organizations, children),
        _FakeLocationLookup({}),
    )
    scope = await resolver.resolve(uuid.uuid4())
    assert scope.level == DashboardScopeLevel.ORGANIZATION
    assert scope.organization_ids == frozenset({msp_id, child_a, child_b})


async def test_scope_resolver_standard_organization_does_not_expand():
    org_id = uuid.uuid4()
    assignments = [
        _FakeAssignment(scope_type=ScopeType.ORGANIZATION.value, organization_id=org_id)
    ]
    organizations = {org_id: _FakeOrganization(id=org_id, org_type="standard")}
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(assignments),
        _FakeOrganizationLookup(organizations),
        _FakeLocationLookup({}),
    )
    scope = await resolver.resolve(uuid.uuid4())
    assert scope.organization_ids == frozenset({org_id})


async def test_scope_resolver_location_scope():
    loc_id = uuid.uuid4()
    assignments = [
        _FakeAssignment(scope_type=ScopeType.LOCATION.value, location_id=loc_id)
    ]
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(assignments),
        _FakeOrganizationLookup({}),
        _FakeLocationLookup({}),
    )
    scope = await resolver.resolve(uuid.uuid4())
    assert scope.level == DashboardScopeLevel.LOCATION
    assert scope.location_ids == frozenset({loc_id})


async def test_scope_resolver_no_assignments_is_none_level():
    resolver = DashboardScopeResolver(
        _FakeRoleResolver([]), _FakeOrganizationLookup({}), _FakeLocationLookup({})
    )
    scope = await resolver.resolve(uuid.uuid4())
    assert scope.level == DashboardScopeLevel.NONE
    assert not scope.allows_organization(uuid.uuid4())


async def test_scope_resolver_resolve_location_organization_id():
    loc_id = uuid.uuid4()
    org_id = uuid.uuid4()
    resolver = DashboardScopeResolver(
        _FakeRoleResolver([]),
        _FakeOrganizationLookup({}),
        _FakeLocationLookup({loc_id: _FakeLocation(id=loc_id, organization_id=org_id)}),
    )
    resolved = await resolver.resolve_location_organization_id(loc_id)
    assert resolved == org_id


def test_grant_scope_used_by_real_role_resolver_still_exposes_expected_fields():
    """Sanity check that this test module's ``_FakeAssignment.grant_scope``
    (via the real ``ActiveRoleAssignment.grant_scope`` property) is
    structurally identical to what ``app.domains.rbac.authorization`` itself
    produces -- so these fakes are not silently testing a different shape."""
    from app.domains.rbac.authorization import ActiveRoleAssignment

    org_id = uuid.uuid4()
    assignment = _FakeAssignment(
        scope_type=ScopeType.ORGANIZATION.value, organization_id=org_id
    )
    active = ActiveRoleAssignment(assignment=assignment, role=assignment.role)
    grant_scope = active.grant_scope
    assert isinstance(grant_scope, GrantScope)
    assert grant_scope.scope_type == ScopeType.ORGANIZATION
    assert grant_scope.organization_id == org_id


# ============================================================================
# DashboardAuditThrottle -- a fake, minimal Redis stand-in
# ============================================================================


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def set(self, key, value, *, nx=False, ex=None):
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True


async def test_dashboard_audit_throttle_first_view_is_audited_then_suppressed():
    redis = _FakeRedis()
    user_id = uuid.uuid4()
    first = await DashboardAuditThrottle.should_write_audit_entry(
        redis, user_id=user_id, dashboard_kind="organization", scope="org-1"
    )
    second = await DashboardAuditThrottle.should_write_audit_entry(
        redis, user_id=user_id, dashboard_kind="organization", scope="org-1"
    )
    assert first is True
    assert second is False


async def test_dashboard_audit_throttle_distinct_scopes_audited_independently():
    redis = _FakeRedis()
    user_id = uuid.uuid4()
    first = await DashboardAuditThrottle.should_write_audit_entry(
        redis, user_id=user_id, dashboard_kind="organization", scope="org-1"
    )
    other_scope = await DashboardAuditThrottle.should_write_audit_entry(
        redis, user_id=user_id, dashboard_kind="organization", scope="org-2"
    )
    assert first is True
    assert other_scope is True


# ============================================================================
# RevenueMetricsResponse -- honest unavailability, never fabricated
# ============================================================================


def test_revenue_metrics_always_unavailable_and_null():
    revenue = RevenueMetricsResponse()
    assert revenue.available is False
    assert revenue.total_revenue is None
    assert revenue.monthly_revenue is None
    assert revenue.arr is None
    assert revenue.mrr is None
    assert "no billing" in revenue.message.lower()


# ============================================================================
# DashboardService -- integration-style tests against hand-rolled fakes
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


def _make_snapshot(**overrides: object) -> AnalyticsSnapshot:
    now = _now()
    fields: dict[str, object] = {
        "organization_id": None,
        "location_id": None,
        "snapshot_type": AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
        "period_start": now - timedelta(days=1),
        "period_end": now,
        "granularity": "daily",
        "metrics": {},
        "computed_at": now,
        "computation_duration_ms": 1.0,
    }
    fields.update(overrides)
    return AnalyticsSnapshot(**_base_fields(**fields))


@dataclass
class _FakeGuestSummary:
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


class _FakeGuestAnalyticsService:
    def __init__(self, summary: _FakeGuestSummary) -> None:
        self._summary = summary
        self.calls: list[tuple] = []

    async def get_summary(self, *, organization_id, location_id, start, end):
        self.calls.append((organization_id, location_id, start, end))
        return self._summary


class _FakeDashboardRepository:
    """Stand-in for ``AnalyticsRepositoryProtocol`` covering only the
    dashboard-relevant surface each test needs."""

    def __init__(self, **overrides: object) -> None:
        self.total_organizations = overrides.get("total_organizations", 3)
        self.total_locations = overrides.get("total_locations", 5)
        self.router_status_rows = overrides.get("router_status_rows", [])
        self.total_guests = overrides.get("total_guests", 100)
        self.platform_guest_aggregate = overrides.get(
            "platform_guest_aggregate", (0, 0)
        )
        self.session_total = overrides.get("session_total", 50)
        self.active_sessions = overrides.get("active_sessions", 2)
        self.session_intervals: list[tuple[datetime, datetime | None]] = overrides.get(
            "session_intervals", []
        )
        self.org_status_counts = overrides.get("org_status_counts", [])
        self.snapshots_by_key: dict[tuple, list[AnalyticsSnapshot]] = overrides.get(
            "snapshots_by_key", {}
        )
        self.active_location_ids_by_org: dict[uuid.UUID, list[uuid.UUID]] = (
            overrides.get("active_location_ids_by_org", {})
        )
        self.auth_rows = overrides.get("auth_rows", [])
        self.otp_stats = overrides.get("otp_stats", OtpStatsRow(0, 0))
        self.voucher_status_counts = overrides.get("voucher_status_counts", {})
        self.captive_portal_counts = overrides.get("captive_portal_counts", (0, 0))
        self.open_alert_counts = overrides.get("open_alert_counts", {})
        self.hour_rows = overrides.get("hour_rows", [])
        self.day_rows = overrides.get("day_rows", [])
        self.user_agent_breakdown = overrides.get(
            "user_agent_breakdown",
            UserAgentBreakdown(0, 0, [], [], []),
        )

    async def count_platform_organizations(self) -> int:
        return self.total_organizations

    async def count_platform_locations(self) -> int:
        return self.total_locations

    async def count_routers_by_status(self, *, organization_id=None, location_id=None):
        return self.router_status_rows

    async def count_platform_guests_total(self) -> int:
        return self.total_guests

    async def get_platform_guest_aggregate(self, *, start, end):
        return self.platform_guest_aggregate

    async def count_guest_sessions_total(
        self, *, organization_id=None, location_id=None
    ):
        return self.session_total

    async def count_active_guest_sessions(
        self, *, organization_id=None, location_id=None
    ):
        return self.active_sessions

    async def list_session_intervals(self, *, organization_id, location_id, start, end):
        return self.session_intervals

    async def count_organizations_by_status(self):
        return self.org_status_counts

    async def get_latest_snapshot(self, *, organization_id, location_id, snapshot_type):
        key = (organization_id, location_id, snapshot_type)
        rows = self.snapshots_by_key.get(key, [])
        return max(rows, key=lambda s: s.period_start) if rows else None

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

        key = (organization_id, location_id, snapshot_type)
        rows = list(self.snapshots_by_key.get(key, []))
        if start is not None:
            rows = [r for r in rows if r.period_start >= start]
        if end is not None:
            rows = [r for r in rows if r.period_start <= end]
        rows.sort(key=lambda s: s.period_start, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        total = len(rows)
        page_rows = rows[params.offset : params.offset + params.page_size]
        return page_rows, PaginationMeta.from_total(params, total)

    async def list_active_location_ids_for_organization(self, organization_id):
        return self.active_location_ids_by_org.get(organization_id, [])

    async def get_auth_method_breakdown(
        self, *, organization_id, location_id, start, end
    ):
        return self.auth_rows

    async def get_otp_stats(self, *, organization_id, location_id, start, end):
        return self.otp_stats

    async def get_voucher_status_counts(self, *, organization_id, location_id):
        return self.voucher_status_counts

    async def count_captive_portal_configs(self, *, organization_id):
        return self.captive_portal_counts

    async def get_open_alert_counts_by_severity(self, *, organization_id, since):
        return self.open_alert_counts

    async def get_session_counts_by_hour(
        self, *, organization_id, location_id, start, end
    ):
        return self.hour_rows

    async def get_session_counts_by_day_of_week(
        self, *, organization_id, location_id, start, end
    ):
        return self.day_rows

    async def get_user_agent_breakdown(
        self, *, organization_id, location_id, start, end
    ):
        return self.user_agent_breakdown


class _FakeAuditWriter:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    async def create_audit_log_entry(self, **fields):
        self.entries.append(fields)
        return None


def _global_service(
    repository, guest_analytics, *, audit_writer=None
) -> DashboardService:
    resolver = DashboardScopeResolver(
        _FakeRoleResolver([_FakeAssignment(scope_type=ScopeType.GLOBAL.value)]),
        _FakeOrganizationLookup({}),
        _FakeLocationLookup({}),
    )
    return DashboardService(
        repository,
        guest_analytics,
        resolver,
        _FakeOrganizationLookup({}),
        _FakeLocationLookup({}),
        _FakeRedis(),
        audit_writer=audit_writer,
    )


async def test_get_super_admin_dashboard_aggregates_and_computes_peak():
    now = _now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    repository = _FakeDashboardRepository(
        total_organizations=4,
        total_locations=9,
        router_status_rows=[("online", 8), ("offline", 2)],
        total_guests=500,
        platform_guest_aggregate=(20, 15),
        session_total=1000,
        active_sessions=12,
        session_intervals=[
            (today_start + timedelta(hours=1), today_start + timedelta(hours=3)),
            (today_start + timedelta(hours=2), today_start + timedelta(hours=4)),
        ],
        org_status_counts=[("trial", 1), ("active", 3)],
    )
    guest_analytics = _FakeGuestAnalyticsService(_FakeGuestSummary(1, 1, 0, None, 0))
    audit_writer = _FakeAuditWriter()
    service = _global_service(repository, guest_analytics, audit_writer=audit_writer)

    result = await service.get_super_admin_dashboard(uuid.uuid4())

    assert result.total_organizations == 4
    assert result.total_locations == 9
    assert result.total_routers == 10
    assert result.routers_online == 8
    assert result.routers_offline == 2
    assert result.total_guests == 500
    assert result.todays_guests == 15
    assert result.monthly_guests == 15
    assert result.total_sessions == 1000
    assert result.active_sessions == 12
    # Peak concurrency: two overlapping intervals -> 2
    assert result.peak_concurrent_sessions == 2
    assert result.trial_customers == 1
    assert result.paid_customers == 3
    assert result.revenue.available is False
    # First view in this window is durably audited.
    assert len(audit_writer.entries) == 1
    assert audit_writer.entries[0]["action"] == "dashboard_super_admin_viewed"


async def test_get_super_admin_dashboard_rejects_non_global_caller():
    repository = _FakeDashboardRepository()
    guest_analytics = _FakeGuestAnalyticsService(_FakeGuestSummary(0, 0, 0, None, 0))
    org_id = uuid.uuid4()
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(
            [
                _FakeAssignment(
                    scope_type=ScopeType.ORGANIZATION.value, organization_id=org_id
                )
            ]
        ),
        _FakeOrganizationLookup({org_id: _FakeOrganization(id=org_id)}),
        _FakeLocationLookup({}),
    )
    service = DashboardService(
        repository,
        guest_analytics,
        resolver,
        _FakeOrganizationLookup({org_id: _FakeOrganization(id=org_id)}),
        _FakeLocationLookup({}),
        _FakeRedis(),
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_super_admin_dashboard(uuid.uuid4())


async def test_get_organization_dashboard_msp_rollup_sums_children():
    msp_id = uuid.uuid4()
    child_id = uuid.uuid4()

    org_snapshot = _make_snapshot(
        organization_id=msp_id,
        metrics={
            "guest_count_unique": 10,
            "session_count_total": 20,
            "session_count_active": 2,
            "router_count_online": 3,
            "router_count_total": 4,
            "total_bandwidth_bytes": 1000,
        },
    )
    child_snapshot = _make_snapshot(
        organization_id=child_id,
        metrics={
            "guest_count_unique": 5,
            "session_count_total": 8,
            "session_count_active": 1,
            "router_count_online": 1,
            "router_count_total": 2,
            "total_bandwidth_bytes": 500,
        },
    )
    repository = _FakeDashboardRepository(
        snapshots_by_key={
            (msp_id, None, AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value): [
                org_snapshot
            ],
            (child_id, None, AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value): [
                child_snapshot
            ],
        },
        active_location_ids_by_org={msp_id: [uuid.uuid4()], child_id: [uuid.uuid4()]},
        router_status_rows=[("online", 4), ("offline", 0)],
    )
    guest_analytics = _FakeGuestAnalyticsService(
        _FakeGuestSummary(
            visitors=20,
            unique_guests=10,
            returning_guests=3,
            average_session_duration_seconds=120.0,
            total_bandwidth_bytes=1000,
        )
    )
    organizations = {
        msp_id: _FakeOrganization(id=msp_id, org_type="msp"),
        child_id: _FakeOrganization(id=child_id, org_type="standard"),
    }
    org_lookup = _FakeOrganizationLookup(
        organizations, {msp_id: [_FakeOrganization(id=child_id)]}
    )
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(
            [
                _FakeAssignment(
                    scope_type=ScopeType.ORGANIZATION.value, organization_id=msp_id
                )
            ]
        ),
        org_lookup,
        _FakeLocationLookup({}),
    )
    service = DashboardService(
        repository,
        guest_analytics,
        resolver,
        org_lookup,
        _FakeLocationLookup({}),
        _FakeRedis(),
    )

    result = await service.get_organization_dashboard(uuid.uuid4(), msp_id)

    assert result.is_msp_rollup is True
    assert len(result.organizations) == 2
    assert result.guest_count_unique == 15  # 10 + 5
    assert result.session_count_total == 28  # 20 + 8
    assert result.session_count_active == 3  # 2 + 1
    assert result.location_count == 2


async def test_get_organization_dashboard_rejects_caller_outside_scope():
    org_id = uuid.uuid4()
    other_org_id = uuid.uuid4()
    repository = _FakeDashboardRepository()
    guest_analytics = _FakeGuestAnalyticsService(_FakeGuestSummary(0, 0, 0, None, 0))
    organizations = {
        org_id: _FakeOrganization(id=org_id),
        other_org_id: _FakeOrganization(id=other_org_id),
    }
    org_lookup = _FakeOrganizationLookup(organizations)
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(
            [
                _FakeAssignment(
                    scope_type=ScopeType.ORGANIZATION.value, organization_id=org_id
                )
            ]
        ),
        org_lookup,
        _FakeLocationLookup({}),
    )
    service = DashboardService(
        repository,
        guest_analytics,
        resolver,
        org_lookup,
        _FakeLocationLookup({}),
        _FakeRedis(),
    )

    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_organization_dashboard(uuid.uuid4(), other_org_id)


async def test_get_location_dashboard_weekly_monthly_sum_from_daily_snapshots():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    now = _now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Three already-closed daily LOCATION_DAILY_SUMMARY snapshots, each
    # session_count_total=10 -- weekly/monthly visitors must be the sum of
    # these plus today's own live (partial) count.
    daily_snapshots = [
        _make_snapshot(
            organization_id=org_id,
            location_id=loc_id,
            snapshot_type=AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value,
            period_start=today_start - timedelta(days=offset),
            period_end=today_start - timedelta(days=offset - 1),
            metrics={"session_count_total": 10},
        )
        for offset in (1, 2, 3)
    ]
    repository = _FakeDashboardRepository(
        snapshots_by_key={
            (
                org_id,
                loc_id,
                AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value,
            ): daily_snapshots
        },
        hour_rows=[(9, 5), (10, 12), (14, 3)],
        day_rows=[(1, 20), (2, 5)],
        user_agent_breakdown=UserAgentBreakdown(
            sessions_total=10,
            sessions_with_user_agent=8,
            by_os=[("Android", 5), ("iOS", 3)],
            by_browser=[("Chrome", 6), ("Safari", 2)],
            by_device_type=[("Mobile", 8)],
        ),
        auth_rows=[("otp_sms", True, 7), ("otp_sms", False, 1), ("voucher", True, 2)],
    )

    class _WindowAwareGuestAnalytics:
        async def get_summary(self, *, organization_id, location_id, start, end):
            if start == today_start:
                return _FakeGuestSummary(
                    visitors=4,
                    unique_guests=3,
                    returning_guests=1,
                    average_session_duration_seconds=90.0,
                    total_bandwidth_bytes=400,
                )
            return _FakeGuestSummary(
                visitors=34,
                unique_guests=15,
                returning_guests=6,
                average_session_duration_seconds=110.0,
                total_bandwidth_bytes=3400,
            )

    org_lookup = _FakeOrganizationLookup({org_id: _FakeOrganization(id=org_id)})
    location_lookup = _FakeLocationLookup(
        {loc_id: _FakeLocation(id=loc_id, organization_id=org_id)}
    )
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(
            [_FakeAssignment(scope_type=ScopeType.LOCATION.value, location_id=loc_id)]
        ),
        org_lookup,
        location_lookup,
    )
    service = DashboardService(
        repository,
        _WindowAwareGuestAnalytics(),
        resolver,
        org_lookup,
        location_lookup,
        _FakeRedis(),
    )

    result = await service.get_location_dashboard(uuid.uuid4(), loc_id)

    # weekly/monthly = sum(daily snapshots' session_count_total) + today's
    # live visitors (4).
    assert result.daily_visitors == 4
    assert result.weekly_visitors == 34  # 3*10 + 4
    assert result.monthly_visitors == 34
    assert result.unique_guests == 15
    assert result.returning_guests == 6
    # Peak hour: the hour with the most sessions (10 -> 12 sessions).
    assert result.peak_hours[0].hour_utc == 10
    assert result.peak_hours[0].session_count == 12
    # Peak day: day 1 with 20 sessions.
    assert result.peak_days[0].day_of_week_utc == 1
    assert result.devices.sessions_with_data == 8
    assert result.devices.sessions_total == 10
    assert any(item.label == "Android" for item in result.devices.by_os)
    assert result.country_statistics.available is False
    auth_by_method = {item.auth_method: item for item in result.auth_methods}
    assert auth_by_method["otp_sms"].successful_attempts == 7
    assert auth_by_method["otp_sms"].failed_attempts == 1


async def test_get_location_dashboard_rejects_caller_outside_scope():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    other_loc_id = uuid.uuid4()
    repository = _FakeDashboardRepository()
    guest_analytics = _FakeGuestAnalyticsService(_FakeGuestSummary(0, 0, 0, None, 0))
    org_lookup = _FakeOrganizationLookup({org_id: _FakeOrganization(id=org_id)})
    location_lookup = _FakeLocationLookup(
        {
            loc_id: _FakeLocation(id=loc_id, organization_id=org_id),
            other_loc_id: _FakeLocation(id=other_loc_id, organization_id=org_id),
        }
    )
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(
            [_FakeAssignment(scope_type=ScopeType.LOCATION.value, location_id=loc_id)]
        ),
        org_lookup,
        location_lookup,
    )
    service = DashboardService(
        repository, guest_analytics, resolver, org_lookup, location_lookup, _FakeRedis()
    )

    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_location_dashboard(uuid.uuid4(), other_loc_id)


async def test_device_breakdown_honest_when_no_user_agent_captured():
    """The honesty path: sessions exist, but none captured a User-Agent
    (e.g. every one predates the capture column) -- reported plainly, never
    fabricated."""
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    repository = _FakeDashboardRepository(
        user_agent_breakdown=UserAgentBreakdown(
            sessions_total=5,
            sessions_with_user_agent=0,
            by_os=[],
            by_browser=[],
            by_device_type=[],
        )
    )
    guest_analytics = _FakeGuestAnalyticsService(_FakeGuestSummary(0, 0, 0, None, 0))
    org_lookup = _FakeOrganizationLookup({org_id: _FakeOrganization(id=org_id)})
    location_lookup = _FakeLocationLookup(
        {loc_id: _FakeLocation(id=loc_id, organization_id=org_id)}
    )
    resolver = DashboardScopeResolver(
        _FakeRoleResolver(
            [_FakeAssignment(scope_type=ScopeType.LOCATION.value, location_id=loc_id)]
        ),
        org_lookup,
        location_lookup,
    )
    service = DashboardService(
        repository, guest_analytics, resolver, org_lookup, location_lookup, _FakeRedis()
    )

    result = await service.get_location_dashboard(uuid.uuid4(), loc_id)

    assert result.devices.available is True
    assert result.devices.sessions_total == 5
    assert result.devices.sessions_with_data == 0
    assert result.devices.by_os == []
    assert result.devices.message is not None


# ============================================================================
# Route registration / RBAC scope wiring -- verified directly off the
# registered routes (mirrors tests/unit/test_analytics.py's own
# introspection pattern)
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
def dashboard_routes_by_path():
    from app.main import create_app

    app = create_app()
    routes: dict[str, object] = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        if path and path.startswith("/api/v1/dashboard/"):
            routes[path] = route
    return routes


@pytest.mark.parametrize(
    ("path", "expected_scope"),
    [
        ("/api/v1/dashboard/super-admin", "global"),
        ("/api/v1/dashboard/organization", "organization"),
        ("/api/v1/dashboard/location", "location"),
    ],
)
def test_dashboard_routes_require_analytics_read_at_expected_scope(
    dashboard_routes_by_path, path, expected_scope
):
    route = dashboard_routes_by_path[path]
    permission_key, scope = _permission_key_and_scope_for_route(route)
    assert permission_key == "analytics.read"
    assert scope == expected_scope


def test_app_boots_with_dashboard_routes_registered_and_no_route_conflicts():
    from app.main import create_app

    app = create_app()
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/api/v1/dashboard/super-admin" in paths
    assert "/api/v1/dashboard/organization" in paths
    assert "/api/v1/dashboard/location" in paths

    seen: set[tuple[str, frozenset[str]]] = set()
    for route in app.routes:
        route_path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if route_path is None or methods is None:
            continue
        key = (route_path, frozenset(methods))
        assert key not in seen, f"duplicate route registered: {key}"
        seen.add(key)

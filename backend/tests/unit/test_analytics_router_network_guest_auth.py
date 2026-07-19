"""Unit tests for BE-012 Part 3 (Router + Network + Guest + Authentication
Analytics): the Internet Availability proxy-signal formula, Guest Retention
formula, Peak Bandwidth formula, bandwidth-from-sessions/hotspot-session
equivalence, WireGuard status composition (verified via a spy), composition
with ``GuestAnalyticsService`` (verified via a spy showing it is actually
called, not re-derived), honest placeholders (disk/temperature/packet-loss/
latency, Top Applications, PMS/Social Login all return ``available: False``),
and tenant-scope rejection on all four new endpoints.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_analytics_dashboards.py``'s own module docstring) -- every
fake below is a small, hand-rolled stand-in for the narrow protocol it
satisfies, no live Postgres/Redis anywhere in this test suite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.analytics.aggregation import new_guest_count
from app.domains.analytics.constants import AnalyticsSnapshotType
from app.domains.analytics.dashboard_aggregation import (
    PeakBandwidthPoint,
    compute_average_speed_bytes_per_second,
    compute_guest_retention_rate,
    compute_peak_bandwidth,
)
from app.domains.analytics.dashboard_scope import DashboardScopeResolver
from app.domains.analytics.domain_analytics_service import DomainAnalyticsService
from app.domains.analytics.exceptions import DashboardScopeForbiddenError
from app.domains.analytics.models import AnalyticsSnapshot
from app.domains.analytics.repository import (
    AuthenticationOutcomeTotals,
    BandwidthRankingRow,
    LanguageBreakdown,
    OtpStatsRow,
    RouterBandwidthRow,
    RouterHealthSnapshotRow,
    RouterSummaryRow,
    UserAgentBreakdown,
)
from app.domains.analytics.router_availability import compute_internet_availability
from app.domains.rbac.enums import ScopeType
from app.domains.router.enums import RouterStatus
from app.domains.wireguard.constants import HealthStatus as WireGuardHealthStatus

# ============================================================================
# router_availability.compute_internet_availability -- the proxy signal
# ============================================================================


def _now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_internet_available_when_online_and_recent_heartbeat():
    now = _now()
    assert (
        compute_internet_availability(
            status=RouterStatus.ONLINE.value,
            last_seen_at=now - timedelta(minutes=2),
            now=now,
        )
        is True
    )


def test_internet_unavailable_when_status_not_online():
    now = _now()
    assert (
        compute_internet_availability(
            status=RouterStatus.OFFLINE.value,
            last_seen_at=now - timedelta(minutes=1),
            now=now,
        )
        is False
    )


def test_internet_unavailable_when_heartbeat_stale():
    """Router.status still says ONLINE but the heartbeat is long gone --
    the exact gap this module's own docstring documents (nothing
    automatically flips Router.status to OFFLINE on staleness alone)."""
    now = _now()
    assert (
        compute_internet_availability(
            status=RouterStatus.ONLINE.value,
            last_seen_at=now - timedelta(hours=5),
            now=now,
        )
        is False
    )


def test_internet_unavailable_when_never_seen():
    now = _now()
    assert (
        compute_internet_availability(
            status=RouterStatus.ONLINE.value, last_seen_at=None, now=now
        )
        is False
    )


# ============================================================================
# dashboard_aggregation.compute_guest_retention_rate
# ============================================================================


def test_guest_retention_rate_basic_formula():
    g1, g2, g3, g4 = (uuid.uuid4() for _ in range(4))
    # previous period: g1, g2, g3 (3 guests). current period: g1, g2, g4 (2 of
    # the 3 previous guests retained).
    rate, retained = compute_guest_retention_rate(
        current_guest_ids={g1, g2, g4}, previous_guest_ids={g1, g2, g3}
    )
    assert retained == 2
    assert rate == pytest.approx(2 / 3 * 100.0)


def test_guest_retention_rate_empty_previous_is_unavailable():
    rate, retained = compute_guest_retention_rate(
        current_guest_ids={uuid.uuid4()}, previous_guest_ids=set()
    )
    assert rate is None
    assert retained == 0


def test_guest_retention_rate_full_retention_is_100_percent():
    g1, g2 = uuid.uuid4(), uuid.uuid4()
    rate, retained = compute_guest_retention_rate(
        current_guest_ids={g1, g2}, previous_guest_ids={g1, g2}
    )
    assert rate == 100.0
    assert retained == 2


# ============================================================================
# dashboard_aggregation.compute_average_speed_bytes_per_second
# ============================================================================


def test_average_speed_bytes_per_second():
    start = _now()
    end = start + timedelta(seconds=100)
    assert compute_average_speed_bytes_per_second(
        total_bytes=1000, window_start=start, window_end=end
    ) == pytest.approx(10.0)


def test_average_speed_zero_duration_is_none():
    start = _now()
    assert (
        compute_average_speed_bytes_per_second(
            total_bytes=1000, window_start=start, window_end=start
        )
        is None
    )


# ============================================================================
# dashboard_aggregation.compute_peak_bandwidth
# ============================================================================


def test_compute_peak_bandwidth_picks_highest_bucket():
    d1 = _now()
    d2 = d1 + timedelta(days=1)
    d3 = d1 + timedelta(days=2)
    buckets = [
        (d1, d1 + timedelta(days=1), 500.0),
        (d2, d2 + timedelta(days=1), 5000.0),
        (d3, d3 + timedelta(days=1), 1200.0),
    ]
    point = compute_peak_bandwidth(buckets)
    assert isinstance(point, PeakBandwidthPoint)
    assert point.bytes_total == 5000.0
    assert point.bucket_start == d2


def test_compute_peak_bandwidth_empty_is_none():
    assert compute_peak_bandwidth([]) is None


# ============================================================================
# aggregation.new_guest_count
# ============================================================================


def test_new_guest_count_formula():
    assert new_guest_count(unique_guests=10, returning_guests=4) == 6


def test_new_guest_count_never_negative():
    assert new_guest_count(unique_guests=2, returning_guests=5) == 0


# ============================================================================
# Fakes shared by every DomainAnalyticsService test below
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
    def __init__(self, organizations, children=None) -> None:
        self._organizations = organizations
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


def _org_scope_resolver(organization_id: uuid.UUID) -> DashboardScopeResolver:
    """A resolver whose only active grant is ORGANIZATION-scoped to
    ``organization_id`` -- the common case every "happy path" test below
    uses."""
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
    """A resolver with zero active assignments -- every ``require_*`` check
    must reject."""
    return DashboardScopeResolver(
        _FakeRoleResolver([]), _FakeOrganizationLookup({}), _FakeLocationLookup({})
    )


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def set(self, key, value, *, nx=False, ex=None):
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True


class _FakeAuditWriter:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    async def create_audit_log_entry(self, **fields):
        self.entries.append(fields)
        return None


class _FakeWireGuardHealth:
    """Spy stand-in for ``WireGuardService.compute_health_status`` -- records
    every call (peer, now) so tests can assert Router Analytics actually
    composes with it rather than re-deriving staleness logic."""

    def __init__(
        self, status: WireGuardHealthStatus = WireGuardHealthStatus.HEALTHY
    ) -> None:
        self.status = status
        self.calls: list[object] = []

    def compute_health_status(self, peer, *, now=None):
        self.calls.append(peer)
        return self.status


@dataclass
class _FakePeer:
    router_id: uuid.UUID
    last_handshake_at: datetime | None


@dataclass
class _FakeGuestSummary:
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


@dataclass
class _FakeTopDevice:
    device_id: uuid.UUID
    mac_address: str
    session_count: int
    unique_guest_count: int


@dataclass
class _FakeTopLocation:
    location_id: uuid.UUID
    location_name: str
    session_count: int


class _FakeGuestAnalyticsService:
    """Spy stand-in for ``GuestAnalyticsService`` -- records every call so
    tests can assert Guest Analytics genuinely composes with it."""

    def __init__(
        self,
        *,
        summary: _FakeGuestSummary,
        top_devices: list[_FakeTopDevice] | None = None,
        top_locations: list[_FakeTopLocation] | None = None,
    ) -> None:
        self._summary = summary
        self._top_devices = top_devices or []
        self._top_locations = top_locations or []
        self.calls: list[tuple[str, tuple]] = []

    async def get_summary(self, *, organization_id, location_id, start, end):
        self.calls.append(("get_summary", (organization_id, location_id, start, end)))
        return self._summary

    async def get_top_devices(self, *, organization_id, start, end, limit=10):
        self.calls.append(("get_top_devices", (organization_id, start, end, limit)))
        return self._top_devices

    async def get_top_locations(self, *, organization_id, start, end, limit=10):
        self.calls.append(("get_top_locations", (organization_id, start, end, limit)))
        return self._top_locations


class _FakeDomainAnalyticsRepository:
    """Stand-in for ``AnalyticsRepositoryProtocol`` covering only the Part 3
    surface ``DomainAnalyticsService`` needs."""

    def __init__(self, **overrides: object) -> None:
        self.routers: list[RouterSummaryRow] = overrides.get("routers", [])
        self.latest_health: dict = overrides.get("latest_health", {})
        self.health_averages: dict = overrides.get("health_averages", {})
        self.bandwidth_by_router: list[RouterBandwidthRow] = overrides.get(
            "bandwidth_by_router", []
        )
        self.wireguard_peers: dict = overrides.get("wireguard_peers", {})
        self.login_failures_by_location: dict = overrides.get(
            "login_failures_by_location", {}
        )
        self.network_bandwidth_totals: tuple[int, int] = overrides.get(
            "network_bandwidth_totals", (0, 0)
        )
        self.snapshots: list[AnalyticsSnapshot] = overrides.get("snapshots", [])
        self.top_guests: list[BandwidthRankingRow] = overrides.get("top_guests", [])
        self.top_locations_bw: list[BandwidthRankingRow] = overrides.get(
            "top_locations_bw", []
        )
        self.top_routers_bw: list[BandwidthRankingRow] = overrides.get(
            "top_routers_bw", []
        )
        self.user_agent_breakdown: UserAgentBreakdown = overrides.get(
            "user_agent_breakdown", UserAgentBreakdown(0, 0, [], [], [])
        )
        self.language_breakdown: LanguageBreakdown = overrides.get(
            "language_breakdown", LanguageBreakdown(0, 0, [])
        )
        self.distinct_guest_ids_by_window: dict = overrides.get(
            "distinct_guest_ids_by_window", {}
        )
        self.otp_stats: OtpStatsRow = overrides.get("otp_stats", OtpStatsRow(0, 0))
        self.voucher_redeemed_count: int = overrides.get("voucher_redeemed_count", 0)
        self.voucher_failed_audit_count: int = overrides.get(
            "voucher_failed_audit_count", 0
        )
        self.outcome_totals: AuthenticationOutcomeTotals = overrides.get(
            "outcome_totals", AuthenticationOutcomeTotals(0, 0, 0)
        )
        self.failure_reasons: list[tuple[str, int]] = overrides.get(
            "failure_reasons", []
        )
        self.daily_trend: list[tuple] = overrides.get("daily_trend", [])
        self.auth_method_rows: list[tuple] = overrides.get("auth_method_rows", [])

    async def list_routers_for_scope(self, *, organization_id, location_id=None):
        return self.routers

    async def get_latest_router_health_snapshots(self, router_ids):
        return self.latest_health

    async def get_router_health_snapshot_averages(self, router_ids, *, start, end):
        return self.health_averages

    async def get_bandwidth_by_router(
        self, *, organization_id, location_id, start, end
    ):
        return self.bandwidth_by_router

    async def get_wireguard_peers_by_router_ids(self, router_ids):
        return self.wireguard_peers

    async def get_login_failure_counts_by_location(self, location_ids, *, start, end):
        return self.login_failures_by_location

    async def get_network_bandwidth_totals(
        self, *, organization_id, location_id, start, end
    ):
        return self.network_bandwidth_totals

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
        return self.snapshots, None

    async def get_top_guests_by_bandwidth(self, *, organization_id, start, end, limit):
        return self.top_guests[:limit]

    async def get_top_locations_by_bandwidth(
        self, *, organization_id, start, end, limit
    ):
        return self.top_locations_bw[:limit]

    async def get_top_routers_by_bandwidth(self, *, organization_id, start, end, limit):
        return self.top_routers_bw[:limit]

    async def get_user_agent_breakdown(
        self, *, organization_id, location_id, start, end
    ):
        return self.user_agent_breakdown

    async def get_language_breakdown(self, *, organization_id, location_id, start, end):
        return self.language_breakdown

    async def get_distinct_guest_ids(self, *, organization_id, location_id, start, end):
        return self.distinct_guest_ids_by_window.get((start, end), set())

    async def get_otp_stats(self, *, organization_id, location_id, start, end):
        return self.otp_stats

    async def get_voucher_redeemed_count(
        self, *, organization_id, location_id, start, end
    ):
        return self.voucher_redeemed_count

    async def get_voucher_redemption_failed_audit_count(
        self, *, organization_id, start, end
    ):
        return self.voucher_failed_audit_count

    async def get_login_history_outcome_totals(
        self, *, organization_id, location_id, start, end
    ):
        return self.outcome_totals

    async def get_login_history_failure_reasons(
        self, *, organization_id, location_id, start, end
    ):
        return self.failure_reasons

    async def get_login_history_daily_trend(
        self, *, organization_id, location_id, start, end
    ):
        return self.daily_trend

    async def get_auth_method_breakdown(
        self, *, organization_id, location_id, start, end
    ):
        return self.auth_method_rows


def _make_service(
    repository: _FakeDomainAnalyticsRepository,
    *,
    organization_id: uuid.UUID,
    guest_analytics: _FakeGuestAnalyticsService | None = None,
    wireguard_health: _FakeWireGuardHealth | None = None,
    scope_resolver: DashboardScopeResolver | None = None,
) -> DomainAnalyticsService:
    return DomainAnalyticsService(
        repository,
        guest_analytics
        or _FakeGuestAnalyticsService(
            summary=_FakeGuestSummary(0, 0, 0, None, 0),
        ),
        scope_resolver or _org_scope_resolver(organization_id),
        wireguard_health or _FakeWireGuardHealth(),
        _FakeRedis(),
    )


# ============================================================================
# Router Analytics
# ============================================================================


async def test_router_analytics_bandwidth_from_sessions_and_hotspot_equivalence():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=router_id,
                router_name="Lobby AP",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            )
        ],
        bandwidth_by_router=[
            RouterBandwidthRow(
                router_id=router_id,
                bytes_uploaded=1000,
                bytes_downloaded=4000,
                session_count=7,
            )
        ],
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )

    item = result.routers[0]
    assert item.bandwidth_uploaded_bytes == 1000
    assert item.bandwidth_downloaded_bytes == 4000
    assert item.bandwidth_total_bytes == 5000
    # Hotspot Sessions == GuestSession count for this router == RADIUS success
    assert item.hotspot_sessions == 7
    assert item.radius_success_count == 7


async def test_router_analytics_cpu_ram_trend_computed_from_average():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=router_id,
                router_name="R1",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            )
        ],
        latest_health={
            router_id: RouterHealthSnapshotRow(
                cpu_usage_percent=80.0,
                memory_usage_percent=60.0,
                uptime_seconds=1000,
                connected_clients_count=5,
                health_status="healthy",
                recorded_at=now,
            )
        },
        health_averages={router_id: (40.0, 30.0)},
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )

    item = result.routers[0]
    assert item.cpu_usage_percent_current == 80.0
    assert item.cpu_usage_trend is not None
    assert item.cpu_usage_trend.direction == "increasing"
    assert item.cpu_usage_trend.previous_value == 40.0
    assert item.memory_usage_trend.direction == "increasing"
    assert item.uptime_seconds == 1000
    assert item.connected_clients_count == 5
    assert item.health_snapshot_available is True


async def test_router_analytics_wireguard_status_composes_with_service():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime.now(UTC)
    peer = _FakePeer(router_id=router_id, last_handshake_at=now)
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=router_id,
                router_name="R1",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            )
        ],
        wireguard_peers={router_id: peer},
    )
    wireguard_health = _FakeWireGuardHealth(status=WireGuardHealthStatus.HEALTHY)
    service = _make_service(
        repository, organization_id=org_id, wireguard_health=wireguard_health
    )

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )

    assert wireguard_health.calls == [peer]  # composed, not re-derived
    assert result.routers[0].wireguard.available is True
    assert result.routers[0].wireguard.status == "healthy"


async def test_router_analytics_wireguard_unavailable_when_no_peer():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=router_id,
                router_name="R1",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            )
        ]
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.routers[0].wireguard.available is False


async def test_router_analytics_internet_availability_reflects_status_and_heartbeat():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    online_recent = uuid.uuid4()
    online_stale = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=online_recent,
                router_name="Fresh",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            ),
            RouterSummaryRow(
                router_id=online_stale,
                router_name="Stale",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now - timedelta(hours=6),
            ),
        ]
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    by_name = {item.router_name: item for item in result.routers}
    assert by_name["Fresh"].internet_available is True
    assert by_name["Stale"].internet_available is False


async def test_router_analytics_radius_failure_is_location_proxy_and_totals():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    router_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=router_id,
                router_name="R1",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            )
        ],
        bandwidth_by_router=[
            RouterBandwidthRow(
                router_id=router_id,
                bytes_uploaded=0,
                bytes_downloaded=0,
                session_count=3,
            )
        ],
        login_failures_by_location={loc_id: 2},
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    item = result.routers[0]
    assert item.radius_success_count == 3
    assert item.radius_failure_count == 2
    assert item.authentication_requests_total == 5


async def test_router_analytics_honest_placeholders():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_router_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.disk_usage.available is False
    assert result.temperature.available is False
    assert result.packet_loss.available is False
    assert result.latency.available is False


async def test_router_analytics_rejects_out_of_scope_organization():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(
        repository, organization_id=org_id, scope_resolver=_no_scope_resolver()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_router_analytics(
            uuid.uuid4(),
            org_id,
            location_id=None,
            start=now - timedelta(days=1),
            end=now,
        )


# ============================================================================
# Network Analytics
# ============================================================================


async def _snapshot(period_start, period_end, total_bandwidth_bytes, **overrides):
    now = datetime.now(UTC)
    fields = {
        "id": uuid.uuid4(),
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
        "organization_id": None,
        "location_id": None,
        "snapshot_type": AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
        "period_start": period_start,
        "period_end": period_end,
        "granularity": "daily",
        "metrics": {"total_bandwidth_bytes": total_bandwidth_bytes},
        "computed_at": now,
        "computation_duration_ms": 1.0,
    }
    fields.update(overrides)
    return AnalyticsSnapshot(**fields)


async def test_network_analytics_peak_bandwidth_from_snapshot_history():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    d1 = now - timedelta(days=2)
    d2 = now - timedelta(days=1)
    snapshots = [
        await _snapshot(d1, d1 + timedelta(days=1), 100),
        await _snapshot(d2, d2 + timedelta(days=1), 9000),
    ]
    repository = _FakeDomainAnalyticsRepository(snapshots=snapshots)
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_network_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=3), end=now
    )
    assert result.peak_bandwidth.available is True
    assert result.peak_bandwidth.peak_bytes == 9000


async def test_network_analytics_peak_bandwidth_unavailable_without_snapshots():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(snapshots=[])
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_network_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=3), end=now
    )
    assert result.peak_bandwidth.available is False
    assert result.peak_bandwidth.peak_bytes is None


async def test_network_analytics_top_rankings_preserve_order():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    g1, g2 = uuid.uuid4(), uuid.uuid4()
    loc1, loc2 = uuid.uuid4(), uuid.uuid4()
    r1, r2 = uuid.uuid4(), uuid.uuid4()
    repository = _FakeDomainAnalyticsRepository(
        top_guests=[
            BandwidthRankingRow(entity_id=g1, label="guest-1", total_bytes=5000),
            BandwidthRankingRow(entity_id=g2, label="guest-2", total_bytes=1000),
        ],
        top_locations_bw=[
            BandwidthRankingRow(entity_id=loc1, label="Lobby", total_bytes=8000),
            BandwidthRankingRow(entity_id=loc2, label="Pool", total_bytes=2000),
        ],
        top_routers_bw=[
            BandwidthRankingRow(entity_id=r1, label="R1", total_bytes=7000),
            BandwidthRankingRow(entity_id=r2, label="R2", total_bytes=3000),
        ],
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_network_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert [c.guest_id for c in result.top_consumers] == [g1, g2]
    assert [item.total_bytes for item in result.top_consumers] == [5000, 1000]
    assert [loc.location_name for loc in result.top_locations] == ["Lobby", "Pool"]
    assert [r.router_name for r in result.top_routers] == ["R1", "R2"]


async def test_network_analytics_totals_and_average_speed():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    start = now - timedelta(seconds=100)
    repository = _FakeDomainAnalyticsRepository(network_bandwidth_totals=(400, 600))
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_network_analytics(
        uuid.uuid4(), org_id, location_id=None, start=start, end=now
    )
    assert result.upload_bytes == 400
    assert result.download_bytes == 600
    assert result.total_bytes == 1000
    assert result.average_speed_bytes_per_second == pytest.approx(10.0)


async def test_network_analytics_availability_rollup():
    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()
    now = datetime.now(UTC)
    online, offline = uuid.uuid4(), uuid.uuid4()
    repository = _FakeDomainAnalyticsRepository(
        routers=[
            RouterSummaryRow(
                router_id=online,
                router_name="Online",
                location_id=loc_id,
                status=RouterStatus.ONLINE.value,
                last_seen_at=now,
            ),
            RouterSummaryRow(
                router_id=offline,
                router_name="Offline",
                location_id=loc_id,
                status=RouterStatus.OFFLINE.value,
                last_seen_at=now,
            ),
        ]
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_network_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.network_availability.available_router_count == 1
    assert result.network_availability.total_router_count == 2
    assert result.network_availability.availability_percent == pytest.approx(50.0)


async def test_network_analytics_top_applications_is_honest_placeholder():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_network_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.top_applications.available is False


async def test_network_analytics_rejects_out_of_scope_organization():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(
        repository, organization_id=org_id, scope_resolver=_no_scope_resolver()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_network_analytics(
            uuid.uuid4(),
            org_id,
            location_id=None,
            start=now - timedelta(days=1),
            end=now,
        )


# ============================================================================
# Guest Analytics
# ============================================================================


async def test_guest_analytics_composes_with_guest_analytics_service():
    """Spy assertion: Guest Analytics genuinely calls into
    GuestAnalyticsService's own methods rather than re-deriving them."""
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    guest_analytics = _FakeGuestAnalyticsService(
        summary=_FakeGuestSummary(
            visitors=20,
            unique_guests=12,
            returning_guests=5,
            average_session_duration_seconds=90.0,
            total_bandwidth_bytes=1200,
        ),
        top_devices=[_FakeTopDevice(uuid.uuid4(), "AA:BB:CC:DD:EE:FF", 4, 2)],
        top_locations=[_FakeTopLocation(uuid.uuid4(), "Lobby", 10)],
    )
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(
        repository, organization_id=org_id, guest_analytics=guest_analytics
    )

    result = await service.get_guest_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )

    called_methods = [name for name, _ in guest_analytics.calls]
    assert "get_summary" in called_methods
    assert "get_top_devices" in called_methods
    assert "get_top_locations" in called_methods
    assert result.unique_guests == 12
    assert result.returning_guests == 5
    # new_guests = max(unique - returning, 0) -- the same formula Part 1 uses
    assert result.new_guests == 7
    # repeat_visits = visitors - unique_guests (sessions beyond first visit)
    assert result.repeat_visits == 8
    assert len(result.top_devices) == 1
    assert result.top_devices[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert len(result.top_locations) == 1
    assert result.average_data_usage_bytes == pytest.approx(1200 / 12)


async def test_guest_analytics_retention_multi_period_fixture():
    """A constructed multi-period fixture: 3 guests in the previous period,
    2 of them retained into the current period plus 1 brand-new guest."""
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    start = now - timedelta(days=7)
    end = now
    previous_start = start - (end - start)
    previous_end = start

    g1, g2, g3, g4 = (uuid.uuid4() for _ in range(4))
    repository = _FakeDomainAnalyticsRepository(
        distinct_guest_ids_by_window={
            (start, end): {g1, g2, g4},
            (previous_start, previous_end): {g1, g2, g3},
        }
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_guest_analytics(
        uuid.uuid4(), org_id, location_id=None, start=start, end=end
    )
    retention = result.guest_retention
    assert retention.available is True
    assert retention.retained_guest_count == 2
    assert retention.retention_rate_percent == pytest.approx(2 / 3 * 100.0)
    assert retention.current_period_guest_count == 3
    assert retention.previous_period_guest_count == 3


async def test_guest_analytics_retention_unavailable_with_no_previous_guests():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(distinct_guest_ids_by_window={})
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_guest_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.guest_retention.available is False
    assert result.guest_retention.retention_rate_percent is None


async def test_guest_analytics_device_and_language_breakdown_classification():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        user_agent_breakdown=UserAgentBreakdown(
            sessions_total=10,
            sessions_with_user_agent=8,
            by_os=[("Android", 5), ("iOS", 3)],
            by_browser=[("Chrome", 6), ("Safari", 2)],
            by_device_type=[("Mobile", 8)],
        ),
        language_breakdown=LanguageBreakdown(
            sessions_total=10,
            sessions_with_language=6,
            by_language=[("en-US", 4), ("fr", 2)],
        ),
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_guest_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.devices.sessions_with_data == 8
    assert any(item.label == "Android" for item in result.devices.by_os)
    assert result.languages.sessions_with_data == 6
    assert {"language": "en-US", "session_count": 4} in result.languages.by_language


async def test_guest_analytics_country_statistics_is_honest_placeholder():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_guest_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.country_statistics.available is False


async def test_guest_analytics_rejects_out_of_scope_organization():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(
        repository, organization_id=org_id, scope_resolver=_no_scope_resolver()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_guest_analytics(
            uuid.uuid4(),
            org_id,
            location_id=None,
            start=now - timedelta(days=1),
            end=now,
        )


# ============================================================================
# Authentication Analytics
# ============================================================================


async def test_authentication_analytics_otp_breakdown():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(otp_stats=OtpStatsRow(10, 7))
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_authentication_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.otp.total_requests == 10
    assert result.otp.successful_count == 7
    assert result.otp.failed_count == 3
    assert result.otp.success_rate == pytest.approx(0.7)


async def test_authentication_analytics_voucher_success_and_partial_failure_note():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository(
        voucher_redeemed_count=15, voucher_failed_audit_count=2
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_authentication_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.voucher.redeemed_count == 15
    assert result.voucher.failed_attempts_recorded == 2
    assert "PARTIAL" in result.voucher.failure_tracking_note


async def test_authentication_analytics_trends_and_failure_reasons():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    day = now.date()
    repository = _FakeDomainAnalyticsRepository(
        outcome_totals=AuthenticationOutcomeTotals(
            total_attempts=12, successful_attempts=9, failed_attempts=3
        ),
        failure_reasons=[("OtpAlreadyConsumedError", 2), ("unknown", 1)],
        daily_trend=[(day, 9, 3)],
    )
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_authentication_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.authentication_success_total == 9
    assert result.authentication_failure_total == 3
    assert result.authentication_trends[0].success_count == 9
    assert result.authentication_trends[0].failure_count == 3
    assert result.failed_login_reasons[0].reason == "OtpAlreadyConsumedError"


async def test_authentication_analytics_pms_and_social_login_are_honest_placeholders():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(repository, organization_id=org_id)

    result = await service.get_authentication_analytics(
        uuid.uuid4(), org_id, location_id=None, start=now - timedelta(days=1), end=now
    )
    assert result.pms_login.available is False
    assert result.social_login.available is False


async def test_authentication_analytics_rejects_out_of_scope_organization():
    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    repository = _FakeDomainAnalyticsRepository()
    service = _make_service(
        repository, organization_id=org_id, scope_resolver=_no_scope_resolver()
    )
    with pytest.raises(DashboardScopeForbiddenError):
        await service.get_authentication_analytics(
            uuid.uuid4(),
            org_id,
            location_id=None,
            start=now - timedelta(days=1),
            end=now,
        )


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
def analytics_routes_by_path():
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
        "/api/v1/analytics/routers",
        "/api/v1/analytics/network",
        "/api/v1/analytics/guests",
        "/api/v1/analytics/authentication",
    ],
)
def test_domain_analytics_routes_require_analytics_read_at_organization_scope(
    analytics_routes_by_path, path
):
    route = analytics_routes_by_path[path]
    permission_key, scope = _permission_key_and_scope_for_route(route)
    assert permission_key == "analytics.read"
    assert scope == "organization"


def test_app_boots_with_domain_analytics_routes_registered_and_no_route_conflicts():
    from app.main import create_app

    app = create_app()
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/api/v1/analytics/routers" in paths
    assert "/api/v1/analytics/network" in paths
    assert "/api/v1/analytics/guests" in paths
    assert "/api/v1/analytics/authentication" in paths

    seen: set[tuple[str, frozenset[str]]] = set()
    for route in app.routes:
        route_path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if route_path is None or methods is None:
            continue
        key = (route_path, frozenset(methods))
        assert key not in seen, f"duplicate route registered: {key}"
        seen.add(key)

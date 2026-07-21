"""Pydantic response schemas for BE-012 Part 2's three dashboard endpoints.

Follows this domain's own ``schemas.py`` conventions (``ConfigDict``,
explicit ``Field`` descriptions). Every "honestly unavailable" figure
(Revenue/ARR/MRR, Country Statistics) uses the same shape: an
``available: bool`` flag plus a human-readable ``message`` explaining why,
with every numeric field ``None`` rather than a fabricated ``0`` or guess --
mirrors ``app.domains.monitoring.constants.HealthStatus.UNKNOWN``'s
"documented, not silently defaulted" honesty posture, adapted to a plain
numeric field instead of an enum.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "GrowthPointResponse",
    "RevenueMetricsResponse",
    "CountryStatisticsResponse",
    "DeviceBreakdownResponse",
    "AuthMethodBreakdownItem",
    "SuperAdminDashboardResponse",
    "PlatformHealthSummaryResponse",
    "UnifiedSuperAdminDashboardResponse",
    "HealthScoreResponse",
    "OrganizationSummaryItem",
    "OrganizationDashboardResponse",
    "PeakHourItem",
    "PeakDayItem",
    "LocationDashboardResponse",
]


class GrowthPointResponse(BaseModel):
    metric: str
    current_value: float
    previous_value: float | None
    delta: float | None
    delta_percent: float | None
    direction: str

    model_config = ConfigDict(from_attributes=True)


class RevenueMetricsResponse(BaseModel):
    """Honest placeholder -- see module docstring. There is no billing/
    subscription/payment domain anywhere in this codebase
    (``Organization.subscription_tier`` is a lightweight, unpopulated label
    only, per Module 005's own documented decision) -- every field here is
    always ``None``."""

    available: bool = False
    total_revenue: float | None = None
    monthly_revenue: float | None = None
    arr: float | None = None
    mrr: float | None = None
    message: str = (
        "Not available: no billing/subscription/payment domain exists in this "
        "codebase. Organization.subscription_tier is a lightweight label only "
        "(see app.domains.organization.models.Organization's module docstring) "
        "with no pricing/entitlement logic behind it."
    )


class CountryStatisticsResponse(BaseModel):
    """Honest placeholder -- there is no GeoIP database, IP-geolocation
    service, or billing/payment data anywhere in this sandbox to derive a
    guest's country from."""

    available: bool = False
    by_country: list[dict[str, object]] = Field(default_factory=list)
    message: str = (
        "Not available: no GeoIP database or IP-geolocation service exists in "
        "this environment, and no billing/payment data exists to derive a "
        "guest's country from another source."
    )


class DeviceBreakdownItem(BaseModel):
    label: str
    session_count: int


class DeviceBreakdownResponse(BaseModel):
    """Top Devices/Browsers/Operating Systems -- see
    ``app.domains.guest.models.GuestSession.user_agent``'s docstring and
    ``app.domains.analytics.repository.AnalyticsRepository
    .get_user_agent_breakdown``'s docstring for the full real-capture-and-
    classify write-up. ``sessions_with_data``/``sessions_total`` make the
    real coverage honest: sessions created before this column existed (or
    where the guest device omitted the header) are real ``NULL``s, not
    silently excluded without a trace."""

    available: bool = True
    sessions_total: int
    sessions_with_data: int
    by_os: list[DeviceBreakdownItem]
    by_browser: list[DeviceBreakdownItem]
    by_device_type: list[DeviceBreakdownItem]
    message: str | None = None


class AuthMethodBreakdownItem(BaseModel):
    auth_method: str
    successful_attempts: int
    failed_attempts: int


class HealthScoreResponse(BaseModel):
    """A heuristic composite score, not a scientific measure -- see
    ``app.domains.analytics.health_score``'s module docstring for the exact
    formula and weights."""

    score: int
    router_health_component: float
    alert_health_component: float
    growth_health_component: float
    router_online_count: int
    router_total_count: int
    open_alert_penalty: float
    growth_direction: str
    formula_note: str = (
        "Heuristic composite: 0.50 x router-online-percentage + 0.30 x "
        "(100 - open-alert-severity-penalty) + 0.20 x guest-growth-direction-"
        "score. Not a scientific or statistically-calibrated measure -- see "
        "app.domains.analytics.health_score's module docstring for the full "
        "write-up of every weight and why."
    )


# ============================================================================
# Super Admin Dashboard
# ============================================================================


class SuperAdminDashboardResponse(BaseModel):
    total_organizations: int
    total_locations: int
    total_routers: int
    routers_online: int
    routers_offline: int

    total_guests: int
    todays_guests: int
    monthly_guests: int

    total_sessions: int
    active_sessions: int
    peak_concurrent_sessions: int
    peak_concurrent_sessions_window_start: str
    peak_concurrent_sessions_window_end: str

    organization_growth: GrowthPointResponse
    location_growth: GrowthPointResponse
    router_growth: GrowthPointResponse
    guest_growth: GrowthPointResponse
    network_growth: GrowthPointResponse

    trial_customers: int
    paid_customers: int
    subscription_note: str = (
        "Trial/Paid are approximated from Organization.status (TRIAL vs. "
        "ACTIVE/SUSPENDED) since Organization.subscription_tier is not "
        "populated anywhere in this codebase's real data paths -- 'paid' "
        "here means 'non-trial, non-archived', not a verified billing "
        "record. See RevenueMetricsResponse for why real revenue figures "
        "are unavailable."
    )
    revenue: RevenueMetricsResponse


class PlatformHealthSummaryResponse(BaseModel):
    """A compact slice of ``app.domains.monitoring.service
    .PlatformDashboardService.get_dashboard_statistics``'s own, richer
    ``PlatformDashboardResult`` -- just the fields the composed
    ``UnifiedSuperAdminDashboardResponse`` needs. The full monitoring
    dashboard (device/ZTP lifecycle breakdowns, etc.) remains available,
    unmodified, at ``GET /monitoring/dashboard``."""

    overall_health_status: str
    alert_counts_by_severity: dict[str, int]
    alert_counts_by_status: dict[str, int]
    device_counts_by_status: dict[str, int]
    average_response_time_ms: float | None
    availability_percentage: float | None


class UnifiedSuperAdminDashboardResponse(BaseModel):
    """Composes three already-existing, separately-callable dashboards --
    this domain's own ``SuperAdminDashboardResponse``,
    ``app.domains.monitoring``'s platform health statistics, and
    ``app.domains.billing``'s Revenue/License figures -- into one payload,
    plus the one genuinely new figure none of them expose: a real
    ``License.status`` breakdown across every organization on the
    platform. None of the three source dashboards are modified, removed,
    or replaced by this -- each remains independently callable exactly as
    before."""

    platform: SuperAdminDashboardResponse
    operations: PlatformHealthSummaryResponse
    license_status_breakdown: dict[str, int]
    total_revenue: float | None
    mrr: float | None
    arr: float | None
    revenue_note: str


# ============================================================================
# Organization Dashboard
# ============================================================================


class OrganizationSummaryItem(BaseModel):
    """One organization's (the caller's own, or -- for an MSP -- one of its
    children) rolled-up summary, from the latest ``ORG_DAILY_SUMMARY``
    snapshot."""

    organization_id: uuid.UUID
    organization_name: str
    guest_count_unique: int
    session_count_total: int
    session_count_active: int
    router_count_online: int
    router_count_total: int
    total_bandwidth_bytes: int
    snapshot_period_start: str | None
    snapshot_period_end: str | None


class OrganizationDashboardResponse(BaseModel):
    organization_id: uuid.UUID
    is_msp_rollup: bool
    organizations: list[OrganizationSummaryItem]

    location_count: int
    router_count: int
    guest_count_unique: int
    session_count_total: int
    session_count_active: int

    captive_portal_active_configs: int
    captive_portal_total_configs: int
    captive_portal_guest_login_volume: int
    captive_portal_note: str = (
        "Captive Portal Usage is guest login volume (GuestSession count) "
        "under this organization's window, since GuestSession carries no "
        "direct foreign key to a specific CaptivePortalConfig row -- a "
        "portal is resolved by (organization_id, location_id), not "
        "referenced per-session. active/total config counts are a real, "
        "direct count of configured portals for context."
    )

    auth_methods: list[AuthMethodBreakdownItem]

    otp_total_requests: int
    otp_verified_count: int
    otp_verification_rate: float

    voucher_status_counts: dict[str, int]

    total_bandwidth_bytes: int
    average_session_duration_seconds: float | None

    peak_hour_utc: int | None
    peak_day_of_week_utc: int | None

    traffic_trend: list[GrowthPointResponse]

    health_score: HealthScoreResponse

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ============================================================================
# Location Dashboard
# ============================================================================


class PeakHourItem(BaseModel):
    hour_utc: int
    session_count: int


class PeakDayItem(BaseModel):
    day_of_week_utc: int
    session_count: int


class LocationDashboardResponse(BaseModel):
    location_id: uuid.UUID
    organization_id: uuid.UUID

    daily_visitors: int
    weekly_visitors: int
    monthly_visitors: int

    unique_guests: int
    returning_guests: int

    average_stay_seconds: float | None

    peak_hours: list[PeakHourItem]
    peak_days: list[PeakDayItem]

    total_bandwidth_bytes: int
    average_session_bandwidth_bytes: float | None
    average_session_duration_seconds: float | None

    devices: DeviceBreakdownResponse
    auth_methods: list[AuthMethodBreakdownItem]

    country_statistics: CountryStatisticsResponse

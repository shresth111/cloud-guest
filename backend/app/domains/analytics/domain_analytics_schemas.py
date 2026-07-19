"""Pydantic response schemas for BE-012 Part 3's four domain analytics
endpoints: ``GET /analytics/routers``, ``/analytics/network``,
``/analytics/guests``, ``/analytics/authentication``.

Follows this domain's own ``dashboard_schemas.py`` conventions exactly
(``ConfigDict``, explicit fields, an ``available: bool`` + ``message`` shape
for every honestly-unavailable figure). Reuses ``dashboard_schemas``'
``GrowthPointResponse``/``DeviceBreakdownResponse``/``DeviceBreakdownItem``/
``AuthMethodBreakdownItem``/``CountryStatisticsResponse`` directly rather
than redefining an equivalent shape a second time.

``UnavailableMetricResponse`` is this file's own one generic placeholder
shape (``available: bool = False`` + ``message``), used for every Part 3
bullet that has **no** extra fields worth a bespoke schema (Router
disk/temperature/packet-loss/latency, Network Top Applications,
Authentication PMS/Social Login) -- unlike Part 2's ``RevenueMetricsResponse``/
``CountryStatisticsResponse``, which each carry their own domain-specific
placeholder fields (``total_revenue``, ``by_country``) alongside
``available``/``message``, so are reused as-is rather than replaced.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

from .dashboard_schemas import (
    AuthMethodBreakdownItem,
    CountryStatisticsResponse,
    DeviceBreakdownResponse,
    GrowthPointResponse,
)

__all__ = [
    "UnavailableMetricResponse",
    "WireGuardStatusItem",
    "RouterAnalyticsItem",
    "RouterAnalyticsResponse",
    "PeakBandwidthResponse",
    "NetworkAvailabilityResponse",
    "TopConsumerItem",
    "TopLocationBandwidthItem",
    "TopRouterBandwidthItem",
    "NetworkAnalyticsResponse",
    "TopDeviceItem",
    "TopLocationItem",
    "GuestRetentionResponse",
    "LanguageStatisticsResponse",
    "GuestAnalyticsResponse",
    "OtpAuthStatsResponse",
    "VoucherAuthStatsResponse",
    "AuthTrendPointItem",
    "FailureReasonItem",
    "AuthenticationAnalyticsResponse",
]


class UnavailableMetricResponse(BaseModel):
    """A generic, honest "not available" placeholder -- ``available`` is
    always ``False`` and every numeric field this bullet would otherwise
    carry is omitted entirely (never a fabricated ``0``/``None`` standing in
    for a real reading), with ``message`` explaining exactly why. See each
    call site's own docstring in ``domain_analytics_service.py`` for the
    specific reasoning (no real MikroTik device/DPI/PMS/social-login
    integration exists in this sandbox)."""

    available: bool = False
    message: str


# ============================================================================
# Router Analytics
# ============================================================================


class WireGuardStatusItem(BaseModel):
    """WireGuard tunnel status for one router -- composes with
    ``app.domains.wireguard.service.WireGuardService.compute_health_status``,
    never re-deriving its staleness-threshold logic. ``available=False``
    means the router has no ``WireGuardPeer`` row at all yet (WireGuard was
    never provisioned for it) -- a real, honest absence, not an error."""

    available: bool
    status: str | None = None
    last_handshake_at: str | None = None
    message: str | None = None


class RouterAnalyticsItem(BaseModel):
    router_id: uuid.UUID
    router_name: str
    location_id: uuid.UUID
    status: str

    cpu_usage_percent_current: float | None
    cpu_usage_trend: GrowthPointResponse | None
    memory_usage_percent_current: float | None
    memory_usage_trend: GrowthPointResponse | None
    uptime_seconds: int | None
    connected_clients_count: int | None
    health_snapshot_available: bool
    health_snapshot_recorded_at: str | None

    bandwidth_uploaded_bytes: int
    bandwidth_downloaded_bytes: int
    bandwidth_total_bytes: int

    internet_available: bool
    last_seen_at: str | None

    wireguard: WireGuardStatusItem

    hotspot_sessions: int
    hotspot_sessions_note: str = (
        "Guest WiFi sessions on this router ARE the hotspot sessions on "
        "this platform -- this is GuestSession count for this router, not "
        "a separate tracked concept."
    )

    authentication_requests_total: int
    radius_success_count: int
    radius_failure_count: int
    radius_failure_scope_note: str = (
        "RADIUS success is exact per-router (GuestSession.router_id). "
        "GuestLoginHistory (where failures are recorded) carries no "
        "router_id column, only location_id -- RADIUS failure is therefore "
        "a location-level proxy, shared across every router co-located at "
        "this router's location, not an exact per-device count."
    )

    model_config = ConfigDict(from_attributes=True)


class RouterAnalyticsResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    window_start: str
    window_end: str

    routers: list[RouterAnalyticsItem]

    disk_usage: UnavailableMetricResponse
    temperature: UnavailableMetricResponse
    packet_loss: UnavailableMetricResponse
    latency: UnavailableMetricResponse


# ============================================================================
# Network Analytics
# ============================================================================


class PeakBandwidthResponse(BaseModel):
    available: bool
    peak_bytes: int | None = None
    bucket_start: str | None = None
    bucket_end: str | None = None
    granularity: str | None = None
    formula_note: str = (
        "The highest total_bandwidth_bytes observed across recent "
        "ORG_DAILY_SUMMARY AnalyticsSnapshot history (one bucket = one "
        "already-computed daily rollup's [period_start, period_end) "
        "window) -- bytes transferred within the busiest bucket, NOT an "
        "instantaneous bits-per-second throughput rate (no such rate "
        "exists anywhere in this codebase's real data)."
    )
    message: str | None = None


class NetworkAvailabilityResponse(BaseModel):
    available_router_count: int
    total_router_count: int
    availability_percent: float | None
    proxy_signal_note: str = (
        "A platform/org-wide rollup of the same Router Analytics Internet "
        "Availability proxy signal (Router.status == ONLINE and a recent "
        "heartbeat) -- not a live internet/uplink probe."
    )


class TopConsumerItem(BaseModel):
    guest_id: uuid.UUID
    identifier: str
    total_bytes: int


class TopLocationBandwidthItem(BaseModel):
    location_id: uuid.UUID
    location_name: str
    total_bytes: int


class TopRouterBandwidthItem(BaseModel):
    router_id: uuid.UUID
    router_name: str
    total_bytes: int


class NetworkAnalyticsResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    window_start: str
    window_end: str

    download_bytes: int
    upload_bytes: int
    total_bytes: int

    peak_bandwidth: PeakBandwidthResponse
    average_speed_bytes_per_second: float | None
    network_availability: NetworkAvailabilityResponse

    top_consumers: list[TopConsumerItem]
    top_locations: list[TopLocationBandwidthItem]
    top_routers: list[TopRouterBandwidthItem]

    traffic_trend: list[GrowthPointResponse]

    top_applications: UnavailableMetricResponse


# ============================================================================
# Guest Analytics
# ============================================================================


class TopDeviceItem(BaseModel):
    device_id: uuid.UUID
    mac_address: str
    session_count: int
    unique_guest_count: int


class TopLocationItem(BaseModel):
    location_id: uuid.UUID
    location_name: str
    session_count: int


class GuestRetentionResponse(BaseModel):
    """Guest Retention -- see ``dashboard_aggregation
    .compute_guest_retention_rate``'s own docstring for the exact formula:
    % of guests seen in the immediately preceding period of equal length who
    were also seen again in the current period."""

    available: bool
    retention_rate_percent: float | None
    retained_guest_count: int
    current_period_guest_count: int
    previous_period_guest_count: int
    period_days: int
    formula_note: str = (
        "retention_rate_percent = |current_period_guests INTERSECT "
        "previous_period_guests| / |previous_period_guests| * 100, where "
        "'previous period' is the immediately preceding period of equal "
        "length to the caller's own window. None/unavailable when the "
        "previous period had zero guests (an undefined ratio, not a real "
        "zero)."
    )
    message: str | None = None


class LanguageStatisticsResponse(BaseModel):
    """Language Statistics -- reuses ``GuestSession.accept_language`` (BE-012
    Part 3's own narrow, additive capture, mirroring ``user_agent``'s exact
    precedent) classified into a primary-language-tag bucket via real SQL at
    read time -- see ``AnalyticsRepository.get_language_breakdown``."""

    available: bool = True
    sessions_total: int
    sessions_with_data: int
    by_language: list[dict[str, object]] = Field(default_factory=list)
    message: str | None = None


class GuestAnalyticsResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    window_start: str
    window_end: str

    new_guests: int
    returning_guests: int
    unique_guests: int
    repeat_visits: int
    repeat_visits_note: str = (
        "Sessions beyond each guest's first visit WITHIN this window "
        "(visitors - unique_guests), distinct from 'returning_guests' "
        "(guests with a lifetime total_visit_count > 1)."
    )

    guest_retention: GuestRetentionResponse

    average_data_usage_bytes: float | None
    average_session_duration_seconds: float | None

    top_devices: list[TopDeviceItem]
    top_locations: list[TopLocationItem]
    devices: DeviceBreakdownResponse
    languages: LanguageStatisticsResponse
    country_statistics: CountryStatisticsResponse

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ============================================================================
# Authentication Analytics
# ============================================================================


class OtpAuthStatsResponse(BaseModel):
    total_requests: int
    successful_count: int
    failed_count: int
    success_rate: float


class VoucherAuthStatsResponse(BaseModel):
    """Voucher Success is real. Voucher Failure is an honestly *partial*
    signal -- see ``AnalyticsRepository
    .get_voucher_redemption_failed_audit_count``'s own docstring for the
    exact gap (only ``revoked``/``exhausted`` reuse attempts are durably
    recorded; routine ``not_found``/``batch_not_active``/``expired``
    failures are structured-log-only, never persisted anywhere queryable)."""

    redeemed_count: int
    failed_attempts_recorded: int
    failure_tracking_note: str = (
        "failed_attempts_recorded is a real but PARTIAL count: only "
        "redemption attempts against an already-revoked/exhausted voucher "
        "are durably audited (AuditAction.VOUCHER_REDEMPTION_FAILED). "
        "Routine failures (code not found, batch not yet active, expired) "
        "are logged via the structured logger only and are not tracked in "
        "any queryable table anywhere in this codebase -- this number is a "
        "lower bound on total voucher failures, not the total."
    )


class AuthTrendPointItem(BaseModel):
    date: str
    success_count: int
    failure_count: int


class FailureReasonItem(BaseModel):
    reason: str
    count: int


class AuthenticationAnalyticsResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    window_start: str
    window_end: str

    otp: OtpAuthStatsResponse
    voucher: VoucherAuthStatsResponse

    authentication_success_total: int
    authentication_failure_total: int
    authentication_trends: list[AuthTrendPointItem]
    failed_login_reasons: list[FailureReasonItem]
    auth_methods: list[AuthMethodBreakdownItem]

    pms_login: UnavailableMetricResponse
    social_login: UnavailableMetricResponse

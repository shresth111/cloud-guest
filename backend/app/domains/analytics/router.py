"""FastAPI routes for the Analytics domain (BE-012 Part 1: Analytics Core
Infrastructure).

A deliberately minimal surface for this infra-focused part -- full
dashboard/per-domain-analytics/forecasting/reporting endpoints are later
BE-012 parts' job, not this one's. Two endpoints:

* ``GET /analytics/snapshots`` -- query already-computed snapshots by
  organization/location/type/date-range.
* ``POST /analytics/snapshots/trigger`` -- manually (re)trigger aggregation
  for one organization (on-demand recomputation, e.g. after a data
  backfill, without waiting for the next Beat tick).

## RBAC permission-key choices

``GET /analytics/snapshots`` uses ``analytics.read`` --
``app.domains.rbac.enums.PermissionModule.ANALYTICS`` is already seeded
(``app.domains.rbac.seed.MODULE_ACTIONS``) with exactly this action, and
``app.domains.guest.router``'s own analytics endpoints already establish
the precedent of gating guest-analytics reads behind this same key.

``POST /analytics/snapshots/trigger`` uses ``reports.manage`` --
``PermissionModule.ANALYTICS`` is seeded with only ``read``/``export``/
``view`` (no ``manage``/``create``/``execute`` action exists for it), so an
admin-gated *write* action (triggering real, if cheap, aggregation work on
demand) has no dedicated ``analytics.*`` key to reuse.
``PermissionModule.REPORTS`` is seeded with ``manage``, and
``app.domains.monitoring.router`` already establishes the precedent of
reusing ``reports.manage`` for an analytics-adjacent admin write action with
no dedicated key of its own (SLA target creation, on-demand SLA report
generation) -- this endpoint follows that exact precedent rather than
inventing a new permission module for one write action.

## Tenant isolation

``GET /analytics/snapshots``' ``organization_id`` is resolved via RBAC's
``CurrentOrganization`` dependency (``X-Organization-Id`` header), not a
raw, unchecked query parameter -- mirrors
``app.domains.guest.router``'s own analytics endpoints (``RequireOrganization``
there; ``CurrentOrganization`` here since an org-less, platform-wide query is
also a legal request for a GLOBAL-scoped caller, e.g. querying
``PLATFORM_DAILY_SUMMARY`` rows). When the header is present,
``CurrentOrganization`` itself validates the organization exists and that
the caller holds an *active* membership in it (raising otherwise) --
exactly the same tenant-isolation guarantee every other domain's own
organization-scoped endpoints already rely on, not reimplemented here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.billing.dependencies import get_super_admin_billing_dashboard_service
from app.domains.billing.service import SuperAdminBillingDashboardService
from app.domains.monitoring.dependencies import get_platform_dashboard_service
from app.domains.monitoring.service import PlatformDashboardService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequireLocation,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .business_schemas import BusinessAnalyticsResponse
from .business_service import BusinessAnalyticsService
from .constants import (
    DEFAULT_ANALYTICS_WINDOW_DAYS,
    TOP_N_DEFAULT,
    TOP_N_MAX,
    AnalyticsSnapshotType,
)
from .dashboard_schemas import (
    LocationDashboardResponse,
    OrganizationDashboardResponse,
    PlatformHealthSummaryResponse,
    SuperAdminDashboardResponse,
    UnifiedSuperAdminDashboardResponse,
)
from .dashboard_service import DashboardService
from .dependencies import (
    get_analytics_service,
    get_business_analytics_service,
    get_dashboard_service,
    get_domain_analytics_service,
    get_forecast_service,
    get_insight_service,
    get_voucher_analytics_service,
)
from .domain_analytics_schemas import (
    AuthenticationAnalyticsResponse,
    GuestAnalyticsResponse,
    NetworkAnalyticsResponse,
    RouterAnalyticsResponse,
)
from .domain_analytics_service import DomainAnalyticsService
from .forecast_schemas import (
    CapacityForecastResponse,
    LinearForecastResponse,
    RouterFailureRiskResponse,
)
from .forecast_service import ForecastService
from .insight_schemas import (
    BusinessInsightsResponse,
    OperationalRecommendationsResponse,
)
from .insight_service import InsightService
from .models import AnalyticsSnapshot
from .report_router import router as report_router
from .schemas import (
    AnalyticsSnapshotListResponse,
    AnalyticsSnapshotResponse,
    TriggerAggregationRequest,
    TriggerAggregationResponse,
)
from .service import AnalyticsService
from .validators import validate_date_range
from .voucher_analytics_schemas import VoucherRedemptionAnalyticsResponse
from .voucher_analytics_service import VoucherAnalyticsService

router = APIRouter(tags=["Analytics"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _resolve_window(
    start_date: datetime | None, end_date: datetime | None
) -> tuple[datetime, datetime]:
    """Resolves the ``[start, end]`` window every BE-012 Part 3 analytics
    endpoint operates over: an explicit, validated caller-supplied range
    when both bounds are given, else a trailing
    ``DEFAULT_ANALYTICS_WINDOW_DAYS``-day window ending now (mirrors this
    domain's own ``validators.day_bounds_utc``'s "sane default when the
    caller supplies nothing" posture)."""
    validate_date_range(start_date, end_date)
    end = end_date or datetime.now(UTC)
    start = start_date or (end - timedelta(days=DEFAULT_ANALYTICS_WINDOW_DAYS))
    return start, end


def _snapshot_response(snapshot: AnalyticsSnapshot) -> AnalyticsSnapshotResponse:
    return AnalyticsSnapshotResponse.model_validate(snapshot)


@router.get(
    "/analytics/snapshots",
    response_model=ApiResponse[AnalyticsSnapshotListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def list_snapshots(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    snapshot_type: AnalyticsSnapshotType | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: AnalyticsService = Depends(get_analytics_service),
):
    items, meta = await service.list_snapshots(
        organization_id=organization_id,
        location_id=location_id,
        snapshot_type=snapshot_type,
        start=start_date,
        end=end_date,
        page=page,
        page_size=page_size,
    )
    payload = AnalyticsSnapshotListResponse(
        items=[_snapshot_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Analytics snapshots retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/analytics/snapshots/trigger",
    response_model=ApiResponse[TriggerAggregationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def trigger_snapshot_aggregation(
    request: Request,
    payload: TriggerAggregationRequest,
    service: AnalyticsService = Depends(get_analytics_service),
):
    snapshots = await service.trigger_aggregation(
        payload.organization_id, target_date_iso=payload.target_date_iso
    )
    response_payload = TriggerAggregationResponse(
        organization_id=payload.organization_id,
        snapshots=[_snapshot_response(item) for item in snapshots],
    )
    return build_response(
        success=True,
        message="Analytics aggregation triggered",
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# BE-012 Part 2: Super Admin + Organization + Location Dashboards
#
# All three are gated by RBAC's ``RequirePermission`` at an explicit scope
# (never inferred) *plus* ``DashboardService``'s own, independent
# ``DashboardScope`` check (see ``dashboard_scope.py``'s module docstring for
# why both layers matter -- "what action" vs. "which tenant's data", the
# identical distinction every other domain's own tenant-scoped endpoints
# already enforce).
# ============================================================================


@router.get(
    "/dashboard/super-admin",
    response_model=ApiResponse[SuperAdminDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read", scope=ScopeType.GLOBAL))],
)
async def get_super_admin_dashboard(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_super_admin_dashboard(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Super Admin dashboard retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/dashboard/super-admin/unified",
    response_model=ApiResponse[UnifiedSuperAdminDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.GLOBAL)),
        Depends(RequirePermission("monitoring.read", scope=ScopeType.GLOBAL)),
        Depends(RequirePermission("billing.read", scope=ScopeType.GLOBAL)),
    ],
)
async def get_unified_super_admin_dashboard(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
    platform_dashboard_service: PlatformDashboardService = Depends(
        get_platform_dashboard_service
    ),
    billing_dashboard_service: SuperAdminBillingDashboardService = Depends(
        get_super_admin_billing_dashboard_service
    ),
):
    """Composes three already-existing, independently-callable dashboards
    (this one's own ``get_super_admin_dashboard``, monitoring's platform
    health statistics, billing's revenue figures) plus one genuinely new
    figure -- a real ``License.status`` breakdown -- into a single
    payload. None of the three source dashboards are modified or replaced;
    each remains callable on its own exactly as before."""
    user_id = uuid.UUID(user.id)
    platform = await dashboard_service.get_super_admin_dashboard(user_id)

    now = datetime.now(UTC)
    operations = await platform_dashboard_service.get_dashboard_statistics(
        organization_id=None, start=now - timedelta(hours=24), end=now
    )

    license_status_breakdown = (
        await billing_dashboard_service.get_license_status_breakdown()
    )
    revenue = await billing_dashboard_service.get_revenue_dashboard(user_id=user_id)

    payload = UnifiedSuperAdminDashboardResponse(
        platform=platform,
        operations=PlatformHealthSummaryResponse(
            overall_health_status=operations.overall_health_status,
            alert_counts_by_severity=operations.alert_counts_by_severity,
            alert_counts_by_status=operations.alert_counts_by_status,
            device_counts_by_status=operations.device_counts_by_status,
            average_response_time_ms=operations.average_response_time_ms,
            availability_percentage=operations.availability_percentage,
        ),
        license_status_breakdown=license_status_breakdown,
        total_revenue=float(revenue.total_revenue),
        mrr=float(revenue.mrr),
        arr=float(revenue.arr),
        revenue_note=revenue.currency_note,
    )
    return build_response(
        success=True,
        message="Unified Super Admin dashboard retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/dashboard/organization",
    response_model=ApiResponse[OrganizationDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_organization_dashboard(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_organization_dashboard(
        uuid.UUID(user.id), organization_id
    )
    return build_response(
        success=True,
        message="Organization dashboard retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/dashboard/location",
    response_model=ApiResponse[LocationDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.LOCATION))
    ],
)
async def get_location_dashboard(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    location_id: uuid.UUID = Depends(RequireLocation),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_location_dashboard(uuid.UUID(user.id), location_id)
    return build_response(
        success=True,
        message="Location dashboard retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# BE-012 Part 3: Router + Network + Guest + Authentication Analytics
#
# Each is gated identically to Part 2's own Organization Dashboard: RBAC's
# RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION) at the
# route, plus DomainAnalyticsService's own, independent DashboardScope check
# (the same DashboardScopeResolver Part 2 built -- see dashboard_scope.py's
# module docstring for why both layers matter). organization_id is resolved
# via RBAC's RequireOrganization (X-Organization-Id header), never a raw,
# unchecked query parameter -- the same tenant-isolation guarantee every
# other organization-scoped endpoint in this codebase already relies on.
# ============================================================================


@router.get(
    "/analytics/routers",
    response_model=ApiResponse[RouterAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_router_analytics(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    service: DomainAnalyticsService = Depends(get_domain_analytics_service),
):
    start, end = _resolve_window(start_date, end_date)
    payload = await service.get_router_analytics(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        start=start,
        end=end,
    )
    return build_response(
        success=True,
        message="Router analytics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/network",
    response_model=ApiResponse[NetworkAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_network_analytics(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    limit: int = Query(default=TOP_N_DEFAULT, ge=1, le=TOP_N_MAX),
    service: DomainAnalyticsService = Depends(get_domain_analytics_service),
):
    start, end = _resolve_window(start_date, end_date)
    payload = await service.get_network_analytics(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        start=start,
        end=end,
        limit=limit,
    )
    return build_response(
        success=True,
        message="Network analytics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/guests",
    response_model=ApiResponse[GuestAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_guest_analytics(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    limit: int = Query(default=TOP_N_DEFAULT, ge=1, le=TOP_N_MAX),
    service: DomainAnalyticsService = Depends(get_domain_analytics_service),
):
    start, end = _resolve_window(start_date, end_date)
    payload = await service.get_guest_analytics(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        start=start,
        end=end,
        limit=limit,
    )
    return build_response(
        success=True,
        message="Guest analytics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/authentication",
    response_model=ApiResponse[AuthenticationAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_authentication_analytics(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    service: DomainAnalyticsService = Depends(get_domain_analytics_service),
):
    start, end = _resolve_window(start_date, end_date)
    payload = await service.get_authentication_analytics(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        start=start,
        end=end,
    )
    return build_response(
        success=True,
        message="Authentication analytics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Phase 1 BhaiFi-parity: Voucher Redemption Analytics
#
# Gated like every other organization-scoped domain analytics endpoint above
# (RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION) +
# RequireOrganization), but -- unlike those -- with no additional
# DashboardScopeResolver check layered underneath; see
# voucher_analytics_service.py's own module docstring for the honest scope
# limitation this implies (no MSP-parent roll-up visibility, in this first
# pass).
# ============================================================================


@router.get(
    "/analytics/voucher-redemptions",
    response_model=ApiResponse[VoucherRedemptionAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_voucher_redemption_analytics(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    service: VoucherAnalyticsService = Depends(get_voucher_analytics_service),
):
    start, end = _resolve_window(start_date, end_date)
    payload = await service.get_voucher_redemption_analytics(
        organization_id=organization_id,
        location_id=location_id,
        start=start,
        end=end,
    )
    return build_response(
        success=True,
        message="Voucher redemption analytics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# BE-012 Part 4: Business Analytics + Forecast Engine + Insight Engine
#
# Business Analytics and both Insight Engine endpoints are inherently
# platform-wide, cross-tenant concepts (Customer Growth/Plan Distribution,
# and the module brief's own illustrative "3 organizations have had..."/
# "location A's guest volume dropped..." examples) -- gated exactly like
# Part 2's Super Admin Dashboard: RequirePermission("analytics.read",
# scope=ScopeType.GLOBAL) plus DashboardScope.require_global(). Forecast
# Engine endpoints are per-organization operational concepts -- gated
# exactly like Part 3's own domain analytics endpoints:
# RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION) plus
# DashboardScope.require_organization(). See each service module's own
# docstring for the full write-up of this scope-design decision.
# ============================================================================


@router.get(
    "/analytics/business",
    response_model=ApiResponse[BusinessAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read", scope=ScopeType.GLOBAL))],
)
async def get_business_analytics(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: BusinessAnalyticsService = Depends(get_business_analytics_service),
):
    payload = await service.get_business_analytics(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Business analytics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/forecast/bandwidth",
    response_model=ApiResponse[LinearForecastResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_bandwidth_forecast(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    forecast_days: int | None = Query(default=None, ge=1, le=90),
    service: ForecastService = Depends(get_forecast_service),
):
    payload = await service.get_bandwidth_forecast(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        forecast_days=forecast_days,
    )
    return build_response(
        success=True,
        message="Bandwidth (traffic) forecast retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/forecast/guest-growth",
    response_model=ApiResponse[LinearForecastResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_guest_growth_forecast(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    forecast_days: int | None = Query(default=None, ge=1, le=90),
    service: ForecastService = Depends(get_forecast_service),
):
    payload = await service.get_guest_growth_forecast(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        forecast_days=forecast_days,
    )
    return build_response(
        success=True,
        message="Guest growth forecast retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/forecast/network-load",
    response_model=ApiResponse[LinearForecastResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_network_load_forecast(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    forecast_days: int | None = Query(default=None, ge=1, le=90),
    service: ForecastService = Depends(get_forecast_service),
):
    payload = await service.get_network_load_forecast(
        uuid.UUID(user.id),
        organization_id,
        location_id=location_id,
        forecast_days=forecast_days,
    )
    return build_response(
        success=True,
        message="Network load forecast retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/forecast/capacity",
    response_model=ApiResponse[CapacityForecastResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_capacity_forecast(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    service: ForecastService = Depends(get_forecast_service),
):
    payload = await service.get_capacity_forecast(
        uuid.UUID(user.id), organization_id, location_id=location_id
    )
    return build_response(
        success=True,
        message="Capacity forecast retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/forecast/router-failure-risk",
    response_model=ApiResponse[RouterFailureRiskResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION))
    ],
)
async def get_router_failure_risk(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    service: ForecastService = Depends(get_forecast_service),
):
    payload = await service.get_router_failure_risk(
        uuid.UUID(user.id), organization_id, location_id=location_id
    )
    return build_response(
        success=True,
        message="Router failure risk retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/insights/business",
    response_model=ApiResponse[BusinessInsightsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read", scope=ScopeType.GLOBAL))],
)
async def get_business_insights(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: InsightService = Depends(get_insight_service),
):
    payload = await service.get_business_insights(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Business insights retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/analytics/insights/operational",
    response_model=ApiResponse[OperationalRecommendationsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read", scope=ScopeType.GLOBAL))],
)
async def get_operational_recommendations(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: InsightService = Depends(get_insight_service),
):
    payload = await service.get_operational_recommendations(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Operational recommendations retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# BE-012 Part 5: Report Engine + Export Engine
#
# All of ``/reports*``'s own routes live in ``report_router.py`` (its own
# module docstring covers the RBAC scope-inference design those routes
# rely on) -- included here so they reach the API through this domain's
# one existing ``app/api/v1/router.py`` registration, with no second,
# separate top-level ``include_router`` call needed for this part.
# ============================================================================

router.include_router(report_router)


__all__ = ["router"]

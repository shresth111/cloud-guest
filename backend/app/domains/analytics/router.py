"""FastAPI router for the Analytics domain."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission, CurrentOrganization
from app.domains.analytics.dependencies import get_analytics_service
from app.domains.analytics.schemas import (
    DashboardKPIsResponse,
    PlatformAnalyticsResponse,
    OrganizationAnalyticsResponse,
    LocationAnalyticsResponse,
    RouterAnalyticsResponse,
    GuestAnalyticsResponse,
    VoucherAnalyticsResponse,
    OTPAnalyticsResponse,
)
from app.domains.analytics.service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["Analytics"])

def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))

@router.get(
    "/dashboard",
    response_model=ApiResponse[DashboardKPIsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_dashboard_kpis(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    kpis = await analytics_service.get_dashboard_kpis(organization_id)
    return build_response(
        success=True,
        message="Dashboard KPIs retrieved successfully",
        data=kpis,
        request_id=_request_id(request),
    )

@router.get(
    "/platform",
    response_model=ApiResponse[PlatformAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_platform_analytics(
    request: Request,
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_platform_analytics()
    return build_response(
        success=True,
        message="Platform analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

@router.get(
    "/organizations",
    response_model=ApiResponse[OrganizationAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_organization_analytics(
    request: Request,
    org_id: uuid.UUID = Query(...),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_organization_analytics(org_id)
    return build_response(
        success=True,
        message="Organization analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

@router.get(
    "/locations",
    response_model=ApiResponse[LocationAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_location_analytics(
    request: Request,
    location_id: uuid.UUID = Query(...),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_location_analytics(location_id)
    return build_response(
        success=True,
        message="Location analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

@router.get(
    "/routers",
    response_model=ApiResponse[RouterAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_router_analytics(
    request: Request,
    router_id: uuid.UUID = Query(...),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_router_analytics(router_id)
    return build_response(
        success=True,
        message="Router analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

@router.get(
    "/guests",
    response_model=ApiResponse[GuestAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_guest_analytics(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_guest_analytics(organization_id)
    return build_response(
        success=True,
        message="Guest analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

@router.get(
    "/vouchers",
    response_model=ApiResponse[VoucherAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_voucher_analytics(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_voucher_analytics(organization_id)
    return build_response(
        success=True,
        message="Voucher analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

@router.get(
    "/otp",
    response_model=ApiResponse[OTPAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_otp_analytics(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    analytics = await analytics_service.get_otp_analytics(organization_id)
    return build_response(
        success=True,
        message="OTP analytics retrieved successfully",
        data=analytics,
        request_id=_request_id(request),
    )

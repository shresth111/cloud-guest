"""FastAPI routes for the Dashboard domain.

Returns dynamic dashboard configuration — overview, sidebar, widgets, and
enabled modules — by composing existing analytics, monitoring, billing, RBAC,
and organization services.

Every endpoint is gated by RBAC's existing ``RequirePermission`` against
``dashboard.read`` (seeded in the RBAC permission table).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_dashboard_service
from .schemas import (
    DashboardModulesResponse,
    DashboardResponse,
    DashboardSidebarResponse,
    DashboardWidgetsResponse,
)
from .service import DashboardService

router = APIRouter(tags=["Dashboard"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/dashboard",
    response_model=ApiResponse[DashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dashboard.read", scope=ScopeType.GLOBAL))],
)
async def get_dashboard(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_dashboard(
        uuid.UUID(user.id), organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Dashboard configuration retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/dashboard/sidebar",
    response_model=ApiResponse[DashboardSidebarResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dashboard.read"))],
)
async def get_dashboard_sidebar(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_sidebar(
        uuid.UUID(user.id), organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Sidebar configuration retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/dashboard/widgets",
    response_model=ApiResponse[DashboardWidgetsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dashboard.read"))],
)
async def get_dashboard_widgets(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_widgets(
        uuid.UUID(user.id), organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Widget configuration retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/dashboard/modules",
    response_model=ApiResponse[DashboardModulesResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dashboard.read"))],
)
async def get_dashboard_modules(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DashboardService = Depends(get_dashboard_service),
):
    payload = await service.get_modules(
        uuid.UUID(user.id), organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Module configuration retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

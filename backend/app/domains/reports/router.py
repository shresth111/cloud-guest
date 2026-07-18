"""FastAPI router for the Reports domain."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission, CurrentOrganization, CurrentUser
from app.domains.auth.models import AuthUser
from app.domains.reports.dependencies import get_reports_service
from app.domains.reports.schemas import (
    ReportResponse,
    ReportCreate,
    ReportScheduleResponse,
    ReportScheduleCreate,
)
from app.domains.reports.service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])

def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))

@router.post(
    "",
    response_model=ApiResponse[ReportResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("reports.create"))],
)
async def generate_report(
    request: Request,
    payload: ReportCreate,
    org_id: uuid.UUID | None = Depends(CurrentOrganization),
    user: AuthUser = Depends(CurrentUser),
    reports_service: ReportService = Depends(get_reports_service),
):
    report = await reports_service.generate_report_demand(
        name=payload.name,
        report_type=payload.report_type,
        file_format=payload.file_format,
        parameters=payload.parameters,
        organization_id=org_id,
        location_id=payload.location_id,
        user_id=uuid.UUID(user.id) if user else None,
    )
    return build_response(
        success=True,
        message="Report generated successfully",
        data=ReportResponse.model_validate(report).model_dump(),
        request_id=_request_id(request),
    )

@router.get(
    "",
    response_model=ApiResponse[list[ReportResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def list_reports(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    reports_service: ReportService = Depends(get_reports_service),
):
    reports = await reports_service.list_reports(limit=limit)
    payload = [ReportResponse.model_validate(item) for item in reports]
    return build_response(
        success=True,
        message="Reports listed successfully",
        data=[item.model_dump() for item in payload],
        request_id=_request_id(request),
    )

@router.post(
    "/schedules",
    response_model=ApiResponse[ReportScheduleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("reports.create"))],
)
async def create_schedule(
    request: Request,
    payload: ReportScheduleCreate,
    org_id: uuid.UUID | None = Depends(CurrentOrganization),
    user: AuthUser = Depends(CurrentUser),
    reports_service: ReportService = Depends(get_reports_service),
):
    schedule = await reports_service.create_schedule(
        name=payload.name,
        report_type=payload.report_type,
        file_format=payload.file_format,
        frequency=payload.frequency,
        recipients=payload.recipients,
        parameters=payload.parameters,
        organization_id=org_id,
        location_id=payload.location_id,
        user_id=uuid.UUID(user.id) if user else None,
    )
    return build_response(
        success=True,
        message="Report schedule created successfully",
        data=ReportScheduleResponse.model_validate(schedule).model_dump(),
        request_id=_request_id(request),
    )

@router.get(
    "/schedules",
    response_model=ApiResponse[list[ReportScheduleResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def list_schedules(
    request: Request,
    org_id: uuid.UUID | None = Depends(CurrentOrganization),
    reports_service: ReportService = Depends(get_reports_service),
):
    if not org_id:
        return build_response(
            success=False,
            message="Organization ID is required",
            status_code=status.HTTP_400_BAD_REQUEST,
            request_id=_request_id(request),
        )
    schedules = await reports_service.get_schedules(org_id)
    payload = [ReportScheduleResponse.model_validate(item) for item in schedules]
    return build_response(
        success=True,
        message="Report schedules retrieved successfully",
        data=[item.model_dump() for item in payload],
        request_id=_request_id(request),
    )

@router.delete(
    "/schedules/{id}",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.delete"))],
)
async def delete_schedule(
    request: Request,
    id: uuid.UUID,
    reports_service: ReportService = Depends(get_reports_service),
):
    await reports_service.delete_schedule(id)
    return build_response(
        success=True,
        message="Report schedule deleted successfully",
        data={},
        request_id=_request_id(request),
    )

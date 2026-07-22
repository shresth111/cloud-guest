"""FastAPI routes for the System domain.

Platform health, status, and version information. Health/readiness probes
are available at ``/health/live`` and ``/health/ready`` — these endpoints
provide richer platform-level information.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission

from .dependencies import get_system_service
from .schemas import SystemHealthResponse, SystemStatusResponse, SystemVersionResponse
from .service import SystemService

router = APIRouter(tags=["System"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/system/health",
    response_model=ApiResponse[SystemHealthResponse],
    status_code=status.HTTP_200_OK,
)
async def get_system_health(
    request: Request,
    service: SystemService = Depends(get_system_service),
):
    payload = await service.get_health()
    return build_response(
        success=True,
        message="System health retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/system/status",
    response_model=ApiResponse[SystemStatusResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_system_status(
    request: Request,
    service: SystemService = Depends(get_system_service),
):
    payload = await service.get_status()
    return build_response(
        success=True,
        message="System status retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/system/version",
    response_model=ApiResponse[SystemVersionResponse],
    status_code=status.HTTP_200_OK,
)
async def get_system_version(
    request: Request,
    service: SystemService = Depends(get_system_service),
):
    payload = await service.get_version()
    return build_response(
        success=True,
        message="System version retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

"""FastAPI routes for Live Session management.

Provides a unified view of active guest sessions and session lifecycle
actions (disconnect, pause, resume, extend) — composing existing guest
domain services.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.auth.models import AuthUser

from .dependencies import get_live_session_service
from .schemas import LiveSessionListResponse, SessionActionResponse
from .service import LiveSessionService

router = APIRouter(tags=["Live Sessions"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/sessions/live",
    response_model=ApiResponse[LiveSessionListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.read"))],
)
async def list_live_sessions(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default="active"),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: LiveSessionService = Depends(get_live_session_service),
):
    payload = await service.list_live_sessions(
        organization_id=organization_id,
        location_id=location_id,
        status=status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return build_response(
        success=True,
        message="Live sessions retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/sessions/{session_id}/disconnect",
    response_model=ApiResponse[SessionActionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_wifi.disconnect"))],
)
async def disconnect_session(
    request: Request,
    session_id: uuid.UUID,
    service: LiveSessionService = Depends(get_live_session_service),
):
    payload = await service.disconnect_session(session_id)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/sessions/{session_id}/pause",
    response_model=ApiResponse[SessionActionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_wifi.update"))],
)
async def pause_session(
    request: Request,
    session_id: uuid.UUID,
    service: LiveSessionService = Depends(get_live_session_service),
):
    payload = await service.pause_session(session_id)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/sessions/{session_id}/resume",
    response_model=ApiResponse[SessionActionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_wifi.update"))],
)
async def resume_session(
    request: Request,
    session_id: uuid.UUID,
    service: LiveSessionService = Depends(get_live_session_service),
):
    payload = await service.resume_session(session_id)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/sessions/{session_id}/extend",
    response_model=ApiResponse[SessionActionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_wifi.update"))],
)
async def extend_session(
    request: Request,
    session_id: uuid.UUID,
    minutes: int = Query(default=30, ge=1, le=1440),
    service: LiveSessionService = Depends(get_live_session_service),
):
    payload = await service.extend_session(session_id, minutes=minutes)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

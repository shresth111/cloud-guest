"""FastAPI routes for the Workspace domain.

Allows users to list, view, and switch between organizations they belong to.
Workspace context is maintained client-side via the X-Organization-Id header.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentOrganization, CurrentUser, RequirePermission

from .dependencies import get_workspace_service
from .schemas import (
    WorkspaceCurrentResponse,
    WorkspaceListResponse,
    WorkspaceSwitchRequest,
    WorkspaceSwitchResponse,
)
from .service import WorkspaceService

router = APIRouter(tags=["Workspace"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/workspaces",
    response_model=ApiResponse[WorkspaceListResponse],
    status_code=status.HTTP_200_OK,
)
async def list_workspaces(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: WorkspaceService = Depends(get_workspace_service),
):
    payload = await service.list_workspaces(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Workspaces retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/workspaces/current",
    response_model=ApiResponse[WorkspaceCurrentResponse],
    status_code=status.HTTP_200_OK,
)
async def get_current_workspace(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: WorkspaceService = Depends(get_workspace_service),
):
    payload = await service.get_current_workspace(
        uuid.UUID(user.id), organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Current workspace retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/workspaces/switch",
    response_model=ApiResponse[WorkspaceSwitchResponse],
    status_code=status.HTTP_200_OK,
)
async def switch_workspace(
    request: Request,
    payload: WorkspaceSwitchRequest,
    user: AuthUser = Depends(CurrentUser),
    service: WorkspaceService = Depends(get_workspace_service),
):
    result = await service.switch_workspace(
        uuid.UUID(user.id), uuid.UUID(payload.organization_id)
    )
    return build_response(
        success=True,
        message=result.message,
        data=result.model_dump(mode="json"),
        request_id=_request_id(request),
    )

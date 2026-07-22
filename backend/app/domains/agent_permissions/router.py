"""FastAPI routes for Agent / Permission management.

Returns suggested roles, permission tree structure, and allows permission
assignment to agents — composing the existing RBAC service.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission

from .dependencies import get_agent_permission_service
from .schemas import (
    AgentPermissionAssignRequest,
    AgentPermissionAssignResponse,
    PermissionTreeResponse,
    SuggestedRoleListResponse,
)
from .service import AgentPermissionService

router = APIRouter(tags=["Agent Permissions"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/roles/suggested",
    response_model=ApiResponse[SuggestedRoleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.read"))],
)
async def get_suggested_roles(
    request: Request,
    service: AgentPermissionService = Depends(get_agent_permission_service),
):
    payload = await service.get_suggested_roles()
    return build_response(
        success=True,
        message="Suggested roles retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/permissions/tree",
    response_model=ApiResponse[PermissionTreeResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("permissions.read"))],
)
async def get_permission_tree(
    request: Request,
    service: AgentPermissionService = Depends(get_agent_permission_service),
):
    payload = await service.get_permission_tree()
    return build_response(
        success=True,
        message="Permission tree retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/agents/{agent_id}/permissions",
    response_model=ApiResponse[AgentPermissionAssignResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.assign"))],
)
async def assign_agent_permissions(
    request: Request,
    agent_id: uuid.UUID,
    body: AgentPermissionAssignRequest,
    service: AgentPermissionService = Depends(get_agent_permission_service),
):
    payload = await service.assign_agent_permissions(agent_id, body)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

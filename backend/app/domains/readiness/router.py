"""FastAPI routes for the Router Readiness Checklist domain."""

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

from .constants import CHECKLIST_ITEMS_BY_KEY
from .dependencies import get_readiness_service
from .models import RouterChecklistItem
from .schemas import (
    ChecklistItemResponse,
    ChecklistResponse,
    ConfirmChecklistItemRequest,
)
from .service import ReadinessService

router = APIRouter(prefix="/readiness", tags=["Router Readiness Checklist"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _item_response(row: RouterChecklistItem) -> ChecklistItemResponse:
    definition = CHECKLIST_ITEMS_BY_KEY[row.item_key]
    return ChecklistItemResponse(
        item_key=row.item_key,
        label=definition.label,
        description=definition.description,
        category=definition.category,
        status=row.status,
        detection_mode=row.detection_mode,
        detail=row.detail,
        evidence=row.evidence or {},
        last_checked_at=row.last_checked_at,
        checked_by_user_id=(
            str(row.checked_by_user_id) if row.checked_by_user_id else None
        ),
    )


@router.get(
    "/routers/{router_id}/checklist",
    response_model=ApiResponse[ChecklistResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("readiness.read"))],
)
async def get_router_checklist(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ReadinessService = Depends(get_readiness_service),
):
    rows = await service.get_checklist(
        router_id, requesting_organization_id=requesting_organization_id
    )
    payload = ChecklistResponse(
        router_id=str(router_id),
        summary=service.summarize(rows),
        items=[_item_response(row) for row in rows],
    )
    return build_response(
        success=True,
        message="Readiness checklist retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/checklist/{item_key}/confirm",
    response_model=ApiResponse[ChecklistItemResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("readiness.manage"))],
)
async def confirm_router_checklist_item(
    request: Request,
    router_id: uuid.UUID,
    item_key: str,
    body: ConfirmChecklistItemRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ReadinessService = Depends(get_readiness_service),
):
    row = await service.confirm_item(
        router_id,
        item_key,
        status=body.status,
        detail=body.detail,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Checklist item updated",
        data=_item_response(row).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

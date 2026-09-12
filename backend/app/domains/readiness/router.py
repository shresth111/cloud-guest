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

from .constants import DEFINITIONS_BY_KEY
from .dependencies import get_readiness_service
from .models import RouterChecklistItem
from .schemas import (
    ChecklistItemResponse,
    ChecklistResponse,
    ConfirmChecklistItemRequest,
    redact_customer_evidence,
)
from .service import ReadinessService

router = APIRouter(prefix="/readiness", tags=["Router Readiness Checklist"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _item_response(row: RouterChecklistItem) -> ChecklistItemResponse:
    """The wire shape for one checklist row.

    ``evidence`` goes through ``redact_customer_evidence`` rather than out
    of the JSONB column verbatim. Both routes in this module are gated on a
    bare ``readiness.read``/``readiness.manage``, i.e. reachable by an
    organization-scoped role, and this domain has no platform-scoped view
    to keep the unredacted copy on -- so the redaction is unconditional
    here rather than a branch on the caller. There is nothing in the
    withheld set a MikroTik checklist emits; see
    ``CUSTOMER_FORBIDDEN_EVIDENCE_KEYS`` for why, and for what a Master
    operator should read instead (the integration's own
    ``/platform/integrations/{id}`` view, which carries all of it).
    """
    definition = DEFINITIONS_BY_KEY[row.item_key]
    return ChecklistItemResponse(
        item_key=row.item_key,
        label=definition.label,
        description=definition.description,
        category=definition.category,
        status=row.status,
        detection_mode=row.detection_mode,
        detail=row.detail,
        evidence=redact_customer_evidence(row.evidence),
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

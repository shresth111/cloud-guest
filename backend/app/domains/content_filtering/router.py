"""FastAPI routes for the Content Filtering domain: per-router
content-filtering rule CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``content_filtering.*`` permission key (see ``app.domains.rbac
.seed`` -- ``PermissionModule.CONTENT_FILTERING``) and resolves
``CurrentOrganization`` (``X-Organization-Id``), passed through to
``ContentFilterService`` as ``requesting_organization_id``.

**Route ordering matters.** ``GET /content-filter-rules`` is registered
before ``GET /content-filter-rules/{rule_id}`` so Starlette's
first-match-wins routing resolves the literal path first, mirroring the
same discipline ``app.domains.firewall.router`` already follows.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import ContentFilterCategory, ContentFilterValueType
from .dependencies import get_content_filter_service
from .models import ContentFilterRule
from .schemas import (
    ContentFilterRuleCreateRequest,
    ContentFilterRuleListResponse,
    ContentFilterRuleResponse,
    ContentFilterRuleUpdateRequest,
    MessageResponse,
)
from .service import ContentFilterService

router = APIRouter(prefix="/content-filter-rules", tags=["Content Filtering"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _rule_response(rule: ContentFilterRule) -> ContentFilterRuleResponse:
    return ContentFilterRuleResponse(
        id=str(rule.id),
        router_id=str(rule.router_id),
        organization_id=str(rule.organization_id),
        location_id=str(rule.location_id),
        name=rule.name,
        category=rule.category,
        value_type=rule.value_type,
        value=rule.value,
        comment=rule.comment,
        is_enabled=rule.is_enabled,
        device_push_status=rule.device_push_status,
        device_push_error=rule.device_push_error,
        device_pushed_at=rule.device_pushed_at,
        created_at=rule.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[ContentFilterRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("content_filtering.create"))],
)
async def create_content_filter_rule(
    request: Request,
    payload: ContentFilterRuleCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    rule = await service.create_rule(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        value_type=payload.value_type,
        value=payload.value,
        category=payload.category,
        comment=payload.comment,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="Content filter rule created",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[ContentFilterRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("content_filtering.read"))],
)
async def list_content_filter_rules(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    rules, meta = await service.list_rules(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = ContentFilterRuleListResponse(
        items=[_rule_response(rule) for rule in rules], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Content filter rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{rule_id}",
    response_model=ApiResponse[ContentFilterRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("content_filtering.read"))],
)
async def get_content_filter_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    rule = await service.get_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Content filter rule retrieved",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{rule_id}",
    response_model=ApiResponse[ContentFilterRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("content_filtering.update"))],
)
async def update_content_filter_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: ContentFilterRuleUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "value_type" in fields:
        fields["value_type"] = ContentFilterValueType(fields["value_type"])
    if "category" in fields:
        fields["category"] = ContentFilterCategory(fields["category"])
    rule = await service.update_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Content filter rule updated",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{rule_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("content_filtering.delete"))],
)
async def delete_content_filter_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    await service.delete_rule(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Content filter rule deleted",
        data=MessageResponse(message="Content filter rule deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{rule_id}/push",
    response_model=ApiResponse[ContentFilterRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("content_filtering.execute"))],
)
async def push_content_filter_rule(
    request: Request,
    rule_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    """Realizes this blocked site on its own router over the RouterOS API.

    Gated by ``content_filtering.execute``, not ``content_filtering
    .update``: editing a row and reaching into a live router are different
    privileges. That action is new -- ``app.domains.rbac.seed`` must be
    re-run on deploy or every operator gets a 403 here.

    **Not ``routers.manage``.** This is a customer-facing screen, and
    ``routers.manage`` folds out of a FULL grant only -- an Organization
    Admin would 403 on the exact button they are meant to press. Every
    other route in this file is gated on this module's own
    ``content_filtering.*`` keys, and this one follows them.

    **There is no try/except in this handler, deliberately.** Every failure
    path raises a ``ContentFilteringError`` carrying its own status code
    (502 for a device connection or operation failure, 409/400/403/404 for
    the rest), and the app-wide ``CloudGuestError`` handler turns it into a
    real non-2xx.

    Returning ``200 {"success": false}`` instead would be invisible: the
    frontend's response interceptor unwraps ``response.data.data`` and
    never reads ``success``, so such a response reaches the UI as a
    success. On this domain that failure mode is the bug -- a customer
    being shown a site as blocked when it is not -- so it must not be
    reintroduced by the endpoint that fixes it.
    """
    rule = await service.push_rule_to_device(
        rule_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Content filter rule pushed to device",
        data=_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

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
from app.domains.rbac.enums import ScopeType

from .constants import ContentFilterCategory, ContentFilterValueType
from .dependencies import get_content_filter_service
from .models import ContentFilterRule
from .schemas import (
    ContentFilterAppListResponse,
    ContentFilterAppResponse,
    ContentFilterAppTargetResponse,
    ContentFilterRuleCreateRequest,
    ContentFilterRuleListResponse,
    ContentFilterRuleResponse,
    ContentFilterRuleUpdateRequest,
    MessageResponse,
)
from .service import AppBlockState, ContentFilterService

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
        app_key=getattr(rule, "app_key", None),
        is_enabled=rule.is_enabled,
        device_push_status=rule.device_push_status,
        device_push_error=rule.device_push_error,
        device_pushed_at=rule.device_pushed_at,
        created_at=rule.created_at,
    )


#: Shown beside the Apps toggles, verbatim. Customer words, no RouterOS.
APP_LIMITATIONS = [
    "This blocks the website names an app uses. It does not recognise the "
    "app itself, so some apps may still get through.",
    "An app that is already open, or that connects without looking up a "
    "name, can keep working until it reconnects.",
    "A device using its own DNS or a VPN, or a phone on mobile data, is not "
    "covered.",
]


def _app_response(state: AppBlockState) -> ContentFilterAppResponse:
    return ContentFilterAppResponse(
        key=state.app.key,
        name=state.app.name,
        category=state.app.category.value,
        note=state.app.note,
        state=state.state,
        push_status=state.push_status,
        targets=[
            ContentFilterAppTargetResponse(
                value_type=t.value_type,
                value=t.value,
                rule_id=str(t.rule_id) if t.rule_id else None,
                owned=t.owned,
                is_enabled=t.is_enabled,
                device_push_status=t.device_push_status,
                device_push_error=t.device_push_error,
            )
            for t in state.targets
        ],
    )


# -- apps ---------------------------------------------------------------------
#
# Registered before every "/{rule_id}" route. ``router_id`` is a PATH
# parameter on purpose: RBAC's scope context reads it from the path and pins
# the permission check to that router's own site (see
# ``app.domains.rbac.dependencies._current_scope_context``), and the service
# re-checks the site against the caller's grants.


@router.get(
    "/routers/{router_id}/apps",
    response_model=ApiResponse[ContentFilterAppListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("content_filtering.read", scope=ScopeType.ROUTER))
    ],
)
async def list_content_filter_apps(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    states = await service.list_app_states(
        router_id, requesting_organization_id=requesting_organization_id
    )
    payload = ContentFilterAppListResponse(
        router_id=str(router_id),
        items=[_app_response(s) for s in states],
        limitations=APP_LIMITATIONS,
    )
    return build_response(
        success=True,
        message="Apps retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/routers/{router_id}/apps/{app_key}",
    response_model=ApiResponse[ContentFilterAppResponse],
    status_code=status.HTTP_200_OK,
    # Creates rows and reaches into the router: both privileges, as the
    # create and push routes require them separately.
    dependencies=[
        Depends(RequirePermission("content_filtering.create", scope=ScopeType.ROUTER)),
        Depends(RequirePermission("content_filtering.execute", scope=ScopeType.ROUTER)),
    ],
)
async def block_content_filter_app(
    request: Request,
    router_id: uuid.UUID,
    app_key: str,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    """Blocks every name of one catalogue app on this router. A partial
    result is a 502 (``CONTENT_FILTER_APP_INCOMPLETE``), never a 200."""
    state = await service.block_app(
        router_id,
        app_key,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="App blocked",
        data=_app_response(state).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/routers/{router_id}/apps/{app_key}",
    response_model=ApiResponse[ContentFilterAppResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("content_filtering.delete", scope=ScopeType.ROUTER))
    ],
)
async def unblock_content_filter_app(
    request: Request,
    router_id: uuid.UUID,
    app_key: str,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    """Removes exactly the rows this app's toggle created -- device first."""
    state = await service.unblock_app(
        router_id,
        app_key,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="App unblocked",
        data=_app_response(state).model_dump(),
        request_id=_request_id(request),
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
    # True on the "Specific websites" list, so rows an app toggle created
    # (dozens of names) never push a hand-blocked site off its one page.
    exclude_app_rules: bool = Query(default=False),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ContentFilterService = Depends(get_content_filter_service),
):
    rules, meta = await service.list_rules(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
        exclude_app_rules=exclude_app_rules,
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

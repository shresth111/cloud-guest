"""FastAPI routes for the URL Shortener domain: the anonymous public-site
create tool, authenticated org-scoped CRUD, Master-console cross-tenant
moderation, and the guest-facing redirect.

## Four distinct routers, one module

Mirrors ``app.domains.guest.router``'s/``app.domains.campaigns.router``'s
own "several ``APIRouter`` instances in one module, each mounted separately
by ``app.api.v1.router``" shape -- each surface here has a genuinely
different authentication/authorization posture, so each gets its own
``APIRouter`` rather than one router with per-route dependency overrides:

* ``public_router`` (``/public/short-links``) -- anonymous, no auth at all.
* ``router`` (``/short-links``) -- authenticated + ``CurrentOrganization``,
  RBAC ``url_shortener.*``.
* ``master_router`` (``/master/short-links``) -- RBAC ``url_shortener.*``
  pinned to ``scope=ScopeType.GLOBAL``, the same platform-admin-only
  pattern ``app.domains.billing.router``/``app.domains.location.router``
  already establish for their own cross-tenant surfaces.
* ``redirect_router`` (``/s``) -- anonymous, no auth, no ``ApiResponse``
  envelope.

## ``POST /public/short-links``/``GET /s/{code}`` carry no
## ``RequirePermission``/``CurrentUser`` dependency at all

Mirrors ``app.domains.otp.router``'s/``app.domains.voucher.router``'s
identical justification: the caller is an anonymous marketing-site visitor
or a browser following a shortened link, neither of whom has a
platform-user identity RBAC could ever grant a permission to. Abuse
protection comes entirely from this module's own rate limiting
(``service.ShortLinkRateLimiter``), not from an authorization check with no
meaningful subject to authorize. Both paths are also listed in
``app.middleware.rate_limit.RATE_LIMITED_PATH_PREFIXES`` for a second,
per-IP-across-all-guest-endpoints layer of defense, the same "defense in
depth, not duplication" posture that middleware's own module docstring
documents for voucher/OTP's identical guest-facing routes.

## ``GET /s/{code}`` is this module's one deliberate deviation from the
## standard envelope

It returns a raw ``302`` redirect, not ``ApiResponse``-wrapped JSON --
mirrors ``app.domains.voucher.router.export_voucher_batch``'s identical
"a redirect/download can't be usefully JSON-wrapped" reasoning (see that
endpoint's own placement/comment). A failure (not found/inactive/expired,
or rate-limited) still flows through the standard global exception handler
as a normal ``ApiResponse``-shaped JSON error body -- only the *success*
path breaks the envelope, since only the success path is a redirect.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import RedirectResponse

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.auth.schemas import MessageResponse
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .constants import ShortLinkSource
from .dependencies import (
    build_short_url,
    get_short_link_service,
    get_short_link_source_ip,
)
from .models import ShortLink
from .schemas import (
    MasterShortLinkModerateRequest,
    ShortLinkCreateRequest,
    ShortLinkCreateResponse,
    ShortLinkListResponse,
    ShortLinkPublicCreateRequest,
    ShortLinkResponse,
    ShortLinkUpdateRequest,
)
from .service import ShortLinkListFilters, ShortLinkService

public_router = APIRouter(prefix="/public/short-links", tags=["URL Shortener"])
router = APIRouter(prefix="/short-links", tags=["URL Shortener"])
master_router = APIRouter(prefix="/master/short-links", tags=["URL Shortener (Master)"])
redirect_router = APIRouter(prefix="/s", tags=["URL Shortener"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _create_response(short_link: ShortLink) -> ShortLinkCreateResponse:
    settings = get_settings()
    return ShortLinkCreateResponse(
        code=short_link.code,
        short_url=build_short_url(short_link.code, settings=settings),
        target_url=short_link.target_url,
        created_at=short_link.created_at,
        expires_at=short_link.expires_at,
    )


def _detail_response(short_link: ShortLink) -> ShortLinkResponse:
    settings = get_settings()
    return ShortLinkResponse(
        id=str(short_link.id),
        code=short_link.code,
        short_url=build_short_url(short_link.code, settings=settings),
        target_url=short_link.target_url,
        organization_id=(
            str(short_link.organization_id) if short_link.organization_id else None
        ),
        created_by_user_id=(
            str(short_link.created_by_user_id)
            if short_link.created_by_user_id
            else None
        ),
        source=short_link.source,
        click_count=short_link.click_count,
        last_clicked_at=short_link.last_clicked_at,
        is_active=short_link.is_active,
        expires_at=short_link.expires_at,
        created_at=short_link.created_at,
        updated_at=short_link.updated_at,
    )


def _list_response(items: list[ShortLink], meta: object) -> ShortLinkListResponse:
    return ShortLinkListResponse(
        items=[_detail_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )


# ============================================================================
# Public, anonymous create (the marketing-site tool) -- no RBAC, see module
# docstring
# ============================================================================


@public_router.post(
    "",
    response_model=ApiResponse[ShortLinkCreateResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_public_short_link(
    request: Request,
    payload: ShortLinkPublicCreateRequest,
    source_ip: str = Depends(get_short_link_source_ip),
    service: ShortLinkService = Depends(get_short_link_service),
):
    short_link = await service.create_public_short_link(
        target_url=payload.target_url, source_ip=source_ip
    )
    return build_response(
        success=True,
        message="Short link created",
        data=_create_response(short_link).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Authenticated, org-scoped customer CRUD
# ============================================================================


@router.post(
    "",
    response_model=ApiResponse[ShortLinkCreateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("url_shortener.create"))],
)
async def create_short_link(
    request: Request,
    payload: ShortLinkCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: ShortLinkService = Depends(get_short_link_service),
):
    short_link = await service.create_customer_short_link(
        target_url=payload.target_url,
        organization_id=organization_id,
        created_by_user_id=uuid.UUID(user.id),
        expires_at=payload.expires_at,
    )
    return build_response(
        success=True,
        message="Short link created",
        data=_create_response(short_link).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[ShortLinkListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("url_shortener.read"))],
)
async def list_short_links(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ShortLinkService = Depends(get_short_link_service),
):
    items, meta = await service.list_short_links(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    return build_response(
        success=True,
        message="Short links retrieved",
        data=_list_response(items, meta).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{short_link_id}",
    response_model=ApiResponse[ShortLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("url_shortener.read"))],
)
async def get_short_link(
    request: Request,
    short_link_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ShortLinkService = Depends(get_short_link_service),
):
    short_link = await service.get_short_link(
        short_link_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Short link retrieved",
        data=_detail_response(short_link).model_dump(),
        request_id=_request_id(request),
    )


@router.patch(
    "/{short_link_id}",
    response_model=ApiResponse[ShortLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("url_shortener.update"))],
)
async def update_short_link(
    request: Request,
    short_link_id: uuid.UUID,
    payload: ShortLinkUpdateRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ShortLinkService = Depends(get_short_link_service),
):
    short_link = await service.update_short_link(
        short_link_id,
        requesting_organization_id=requesting_organization_id,
        data=payload.model_dump(exclude_unset=True),
    )
    return build_response(
        success=True,
        message="Short link updated",
        data=_detail_response(short_link).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{short_link_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("url_shortener.delete"))],
)
async def revoke_short_link(
    request: Request,
    short_link_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ShortLinkService = Depends(get_short_link_service),
):
    await service.revoke_short_link(
        short_link_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Short link revoked",
        data=MessageResponse(message="Short link revoked").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Master console: cross-tenant list/search/filter + moderation
# ============================================================================


@master_router.get(
    "",
    response_model=ApiResponse[ShortLinkListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("url_shortener.read", scope=ScopeType.GLOBAL))
    ],
)
async def master_list_short_links(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    organization_id: uuid.UUID | None = Query(default=None),
    source: ShortLinkSource | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    service: ShortLinkService = Depends(get_short_link_service),
):
    items, meta = await service.list_short_links(
        requesting_organization_id=None,
        page=page,
        page_size=page_size,
        extra_filters=ShortLinkListFilters(
            organization_id=organization_id,
            source=source.value if source else None,
            is_active=is_active,
        ),
    )
    return build_response(
        success=True,
        message="Short links retrieved",
        data=_list_response(items, meta).model_dump(),
        request_id=_request_id(request),
    )


@master_router.patch(
    "/{short_link_id}",
    response_model=ApiResponse[ShortLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("url_shortener.update", scope=ScopeType.GLOBAL))
    ],
)
async def master_moderate_short_link(
    request: Request,
    short_link_id: uuid.UUID,
    payload: MasterShortLinkModerateRequest,
    service: ShortLinkService = Depends(get_short_link_service),
):
    short_link = await service.master_moderate_short_link(
        short_link_id, data=payload.model_dump(exclude_unset=True)
    )
    return build_response(
        success=True,
        message="Short link moderated",
        data=_detail_response(short_link).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Guest-facing redirect -- no RBAC, no ApiResponse envelope, see module
# docstring
# ============================================================================


@redirect_router.get("/{code}", status_code=status.HTTP_302_FOUND)
async def redirect_short_link(
    code: str,
    source_ip: str = Depends(get_short_link_source_ip),
    service: ShortLinkService = Depends(get_short_link_service),
) -> RedirectResponse:
    short_link = await service.resolve_and_record_click(code, source_ip=source_ip)
    return RedirectResponse(
        url=short_link.target_url, status_code=status.HTTP_302_FOUND
    )


__all__ = ["public_router", "router", "master_router", "redirect_router"]

"""FastAPI routes for the Branding domain.

Per-organization branding configuration — company name, logo, favicon,
color scheme, and theme. Every endpoint returns non-null branding data:
if an organization has no branding row, the platform default is returned.

All endpoints are gated by RBAC's existing ``RequirePermission`` against
``white_label.*`` permission keys (already seeded) and resolve the
organization context via ``RequireOrganization`` / ``CurrentOrganization``.
"""

from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, Depends, File, Request, Response, UploadFile, status

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)

from .dependencies import get_branding_service
from .schemas import BrandingResponse, BrandingUpdateRequest, DefaultBrandingResponse
from .service import BrandingService

router = APIRouter(tags=["Branding"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _asset_response(
    request: Request,
    *,
    content: bytes,
    content_type: str,
    visibility: str,
) -> Response:
    """Builds the actual image response for every logo/background-image
    serving endpoint below, with real browser caching: a strong ETag
    hashed from the returned bytes (content-addressed -- see
    ``Settings.branding_asset_cache_ttl_seconds``'s own docstring for why
    that's correct even though the URL itself never changes) plus a
    ``Cache-Control`` max-age.

    Without this, every one of these endpoints -- including
    ``get_logo_public``/``get_background_image_public``, exactly what a
    guest's browser fetches on every single WiFi join per
    ``GET /captive-portal/resolve`` -- shipped zero cache headers at all:
    a full re-download of the same bytes on every page load, repeat guest
    visit, and every other guest device at the same location, with no way
    for the browser (or any intermediary) to skip or cheapen the request.

    ``visibility`` is ``"public"`` for the unauthenticated guest-facing
    paths (safe for a shared/intermediary cache to store -- same asset
    every guest at this location already sees unauthenticated) and
    ``"private"`` for the authenticated admin-dashboard raw paths (gated
    by an RBAC permission that varies per caller, so only that caller's
    own browser should cache it, not a shared cache in between).
    """
    etag = hashlib.sha256(content).hexdigest()
    quoted_etag = f'"{etag}"'
    ttl = get_settings().branding_asset_cache_ttl_seconds
    headers = {
        "Cache-Control": f"{visibility}, max-age={ttl}, must-revalidate",
        "ETag": quoted_etag,
    }
    if_none_match = request.headers.get("if-none-match")
    if if_none_match is not None and quoted_etag in {
        tag.strip() for tag in if_none_match.split(",")
    }:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return Response(content=content, media_type=content_type, headers=headers)


@router.get(
    "/branding",
    # Union, not just BrandingResponse: an organization with no branding
    # row yet gets DefaultBrandingResponse back (see get_branding's own
    # docstring) -- that shape has no id/organization_id, so declaring
    # this as BrandingResponse alone made FastAPI's own response
    # validation 500 on every organization that had never configured
    # branding (a pre-existing bug this endpoint had never actually been
    # exercised against until BrandAssetPage.tsx started calling it for
    # real).
    response_model=ApiResponse[BrandingResponse | DefaultBrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.read")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def get_branding(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Get branding for the current organization.

    Returns the organization's branding if configured, otherwise returns
    the platform default branding. Never returns null.
    """
    payload = await service.get_branding(organization_id)
    return build_response(
        success=True,
        message="Branding retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/branding",
    response_model=ApiResponse[BrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.update")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def update_branding(
    request: Request,
    body: BrandingUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Create or update branding for the current organization."""
    payload = await service.update_branding(
        organization_id,
        body,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Branding updated",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/branding/background-image",
    response_model=ApiResponse[BrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.update")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def upload_background_image(
    request: Request,
    file: UploadFile = File(...),
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Uploads (replacing any existing) the login-screen background image
    for the current organization. Stores the file via the platform's
    existing S3/MinIO-compatible object storage and returns branding data
    with a fresh, ready-to-render ``background_image_url``.
    """
    content = await file.read()
    payload = await service.upload_background_image(
        organization_id,
        filename=file.filename or "background-image",
        content_type=file.content_type or "application/octet-stream",
        content=content,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Background image updated",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/branding/background-image/raw",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.read")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def get_background_image_raw(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Streams the current organization's background image bytes.

    ``background_image_url`` in ``GET/PUT /branding`` and the upload/
    delete responses is this exact path -- an ``<img>`` tag can't send an
    Authorization header, so the frontend fetches this authenticated
    (same as every other branding call) and renders it via a local blob
    URL, rather than this being a directly-linkable public image URL.
    """
    content, content_type = await service.get_background_image_bytes(organization_id)
    return _asset_response(
        request, content=content, content_type=content_type, visibility="private"
    )


@router.delete(
    "/branding/background-image",
    response_model=ApiResponse[BrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.update")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def delete_background_image(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Removes the current organization's login-screen background image."""
    payload = await service.delete_background_image(
        organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Background image removed",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/branding/logo",
    response_model=ApiResponse[BrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.update")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def upload_logo(
    request: Request,
    file: UploadFile = File(...),
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Uploads (replacing any existing) the logo for the current
    organization. Stores the file via the platform's existing S3/MinIO-
    compatible object storage and returns branding data with a fresh,
    ready-to-render ``logo_url``. Mirrors ``POST /branding/background-image``
    exactly.
    """
    content = await file.read()
    payload = await service.upload_logo(
        organization_id,
        filename=file.filename or "logo",
        content_type=file.content_type or "application/octet-stream",
        content=content,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Logo updated",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/branding/logo/raw",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.read")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def get_logo_raw(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Streams the current organization's uploaded logo bytes. Mirrors
    ``GET /branding/background-image/raw`` exactly -- see that endpoint's
    own docstring for why this is an authenticated proxy, not a
    directly-linkable public image URL.
    """
    content, content_type = await service.get_logo_bytes(organization_id)
    return _asset_response(
        request, content=content, content_type=content_type, visibility="private"
    )


@router.delete(
    "/branding/logo",
    response_model=ApiResponse[BrandingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("white_label.update")),
        Depends(RequireFeature(PlanFeatureKey.WHITE_LABEL)),
    ],
)
async def delete_logo(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BrandingService = Depends(get_branding_service),
):
    """Removes the current organization's uploaded logo (falls back to
    the plain-text ``logo_url`` column, if any -- see
    BrandingService._resolve_logo_url)."""
    payload = await service.delete_logo(
        organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Logo removed",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/branding/{organization_id}/logo/public",
    status_code=status.HTTP_200_OK,
)
async def get_logo_public(
    request: Request,
    organization_id: uuid.UUID,
    service: BrandingService = Depends(get_branding_service),
):
    """Streams an organization's uploaded logo bytes with **no auth at
    all** -- the guest-facing counterpart to ``GET /branding/logo/raw``.

    A real captive-portal guest has no platform-user identity RBAC could
    ever grant a permission to (same class of exception
    ``GET /captive-portal/resolve`` and ``app.domains.otp``/
    ``app.domains.voucher``'s own guest-facing endpoints already are --
    see this module's own architecture note and each of those routers'
    matching justification). Exposing this asset unauthenticated is not
    a meaningfully bigger disclosure than the guest already has: it's
    the exact same logo already rendered on their own screen the moment
    the captive portal loads, before they've authenticated by any
    method. ``organization_id`` is an explicit path param (not header-
    derived) since there is no ``X-Organization-Id``/session to derive
    it from pre-auth -- mirrors ``GET /captive-portal/resolve``'s own
    query-param identity for the same reason.
    """
    content, content_type = await service.get_logo_bytes(organization_id)
    return _asset_response(
        request, content=content, content_type=content_type, visibility="public"
    )


@router.get(
    "/branding/{organization_id}/background-image/public",
    status_code=status.HTTP_200_OK,
)
async def get_background_image_public(
    request: Request,
    organization_id: uuid.UUID,
    service: BrandingService = Depends(get_branding_service),
):
    """Streams an organization's login-screen background image bytes
    with no auth -- mirrors ``get_logo_public`` exactly, see that
    endpoint's own docstring for the full reasoning."""
    content, content_type = await service.get_background_image_bytes(organization_id)
    return _asset_response(
        request, content=content, content_type=content_type, visibility="public"
    )


@router.get(
    "/branding/default",
    response_model=ApiResponse[DefaultBrandingResponse],
    status_code=status.HTTP_200_OK,
)
async def get_default_branding(
    request: Request,
    service: BrandingService = Depends(get_branding_service),
):
    """Get the platform default branding configuration."""
    payload = await service.get_default_branding()
    return build_response(
        success=True,
        message="Default branding retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

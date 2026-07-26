"""FastAPI routes for the Branding domain.

Per-organization branding configuration — company name, logo, favicon,
color scheme, and theme. Every endpoint returns non-null branding data:
if an organization has no branding row, the platform default is returned.

All endpoints are gated by RBAC's existing ``RequirePermission`` against
``white_label.*`` permission keys (already seeded) and resolve the
organization context via ``RequireOrganization`` / ``CurrentOrganization``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, Request, Response, UploadFile, status

from app.common.responses import ApiResponse, build_response
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
    return Response(content=content, media_type=content_type)


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

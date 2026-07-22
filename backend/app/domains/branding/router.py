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

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature

from .dependencies import get_branding_service
from .schemas import BrandingResponse, BrandingUpdateRequest, DefaultBrandingResponse
from .service import BrandingService

router = APIRouter(tags=["Branding"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/branding",
    response_model=ApiResponse[BrandingResponse],
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

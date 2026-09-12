"""FastAPI routes for Feature Entitlement.

Returns available platform features and a customer's real entitlements.
Feature definitions are driven by the billing domain's PlanFeatureKey enum.

``customer_id`` in the ``/customers/{customer_id}/...`` routes below **is an
organization id** -- it is handed straight to
``LicenseService.get_entitlement_snapshot(organization_id)``. The parameter
name is historical; there is no separate "customer" entity in this codebase.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.scoping import enforce_target_organization
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_feature_entitlement_service
from .schemas import (
    CustomerFeaturesResponse,
    CustomerFeaturesUpdateRequest,
    CustomerFeaturesUpdateResponse,
    FeatureListResponse,
)
from .service import FeatureEntitlementService

router = APIRouter(tags=["Features"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "/features",
    response_model=ApiResponse[FeatureListResponse],
    status_code=status.HTTP_200_OK,
)
async def list_features(
    request: Request,
    service: FeatureEntitlementService = Depends(get_feature_entitlement_service),
):
    payload = await service.list_features()
    return build_response(
        success=True,
        message="Features retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/me/entitlements",
    response_model=ApiResponse[CustomerFeaturesResponse],
    status_code=status.HTTP_200_OK,
)
async def get_my_entitlements(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: FeatureEntitlementService = Depends(get_feature_entitlement_service),
):
    """The caller's own organization's entitlements.

    Carries no ``RequirePermission``, deliberately, exactly like
    ``GET /me/permissions``. Reading what *your own* organization is entitled
    to is not a privileged act -- reading someone else's is, which is what
    ``/customers/{customer_id}/features`` below is gated for.

    That distinction matters more here than it looks. The dashboard uses
    entitlements to decide which features to lock, and it has to do that for
    **every** signed-in user. The only entitlement read available was gated on
    ``billing.read``, which an Organization Owner holds and a front-desk staff
    member does not -- so the locked-feature UI worked for owners and silently
    failed open for staff. A permission gate that turns "you may not ask" into
    "everything appears unlocked" is the exact failure shape this codebase has
    been removing, so the self-read is ungated and the answer is always the
    caller's own organization, never one they name.

    A platform-level caller (no organization context) has no entitlements of
    their own to report -- their authority comes from a GLOBAL role, not a
    plan -- so they get an empty feature list rather than a 400.
    """
    if organization_id is None:
        payload = CustomerFeaturesResponse(customer_id=user.id, features=[])
    else:
        payload = await service.get_customer_features(organization_id)
    return build_response(
        success=True,
        message="Your entitlements",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/customers/{customer_id}/features",
    response_model=ApiResponse[CustomerFeaturesResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_customer_features(
    request: Request,
    customer_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
    service: FeatureEntitlementService = Depends(get_feature_entitlement_service),
):
    # `customer_id` is an organization id taken from the path, while
    # `RequirePermission` above resolves its scope from the header -- the
    # header/path defect class this codebase already has a guard for. The
    # usual path-parameter fallback in `_current_scope_context` does not cover
    # it, because that looks for a parameter literally named
    # `organization_id`. Without this, any tenant holding `billing.read` on
    # its own organization could read another tenant's plan and limits.
    await enforce_target_organization(
        target_organization_id=customer_id,
        requesting_organization_id=requesting_organization_id,
        organization_service=organization_service,
    )
    payload = await service.get_customer_features(customer_id)
    return build_response(
        success=True,
        message="Customer features retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/customers/{customer_id}/features",
    response_model=ApiResponse[CustomerFeaturesUpdateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.manage"))],
)
async def update_customer_features(
    request: Request,
    customer_id: uuid.UUID,
    body: CustomerFeaturesUpdateRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    organization_service: OrganizationService = Depends(get_organization_service),
    service: FeatureEntitlementService = Depends(get_feature_entitlement_service),
):
    # Same guard as the read above. This endpoint raises 501 today, but the
    # tenant check belongs on it regardless -- whoever implements a real
    # override model should not have to remember to add it.
    await enforce_target_organization(
        target_organization_id=customer_id,
        requesting_organization_id=requesting_organization_id,
        organization_service=organization_service,
    )
    payload = await service.update_customer_features(customer_id, body.features)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

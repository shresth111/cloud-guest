"""FastAPI routes for Feature Entitlement.

Returns available platform features and manages per-customer feature toggles.
Feature definitions are driven by the billing domain's PlanFeatureKey enum.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission
from app.domains.rbac.enums import ScopeType

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
    "/customers/{customer_id}/features",
    response_model=ApiResponse[CustomerFeaturesResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_customer_features(
    request: Request,
    customer_id: uuid.UUID,
    service: FeatureEntitlementService = Depends(get_feature_entitlement_service),
):
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
    service: FeatureEntitlementService = Depends(get_feature_entitlement_service),
):
    payload = await service.update_customer_features(customer_id, body.features)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

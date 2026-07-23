"""FastAPI routes for Customer Provisioning.

Complete onboarding workflow — organization creation, configuration script
generation, NAS registration, and WireGuard setup — composing existing
domain services.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .dependencies import get_customer_provisioning_service
from .schemas import (
    GenerateNasResponse,
    GenerateScriptResponse,
    OnboardRequest,
    OnboardResponse,
    WireguardConfigResponse,
)
from .service import CustomerProvisioningService

router = APIRouter(tags=["Customer Provisioning"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.post(
    "/customers/onboard",
    response_model=ApiResponse[OnboardResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("organizations.create"))],
)
async def onboard_customer(
    request: Request,
    body: OnboardRequest,
    user: AuthUser = Depends(CurrentUser),
    service: CustomerProvisioningService = Depends(get_customer_provisioning_service),
):
    payload = await service.onboard(body, uuid.UUID(user.id))
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/customers/{customer_id}/generate-script",
    response_model=ApiResponse[GenerateScriptResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.create"))],
)
async def generate_customer_script(
    request: Request,
    customer_id: uuid.UUID,
    service: CustomerProvisioningService = Depends(get_customer_provisioning_service),
):
    payload = await service.generate_script(customer_id)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/customers/{customer_id}/generate-nas",
    response_model=ApiResponse[GenerateNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_wifi.create"))],
)
async def generate_customer_nas(
    request: Request,
    customer_id: uuid.UUID,
    service: CustomerProvisioningService = Depends(get_customer_provisioning_service),
):
    payload = await service.generate_nas(customer_id)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/customers/{customer_id}/wireguard",
    response_model=ApiResponse[WireguardConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("wireguard.create"))],
)
async def generate_customer_wireguard(
    request: Request,
    customer_id: uuid.UUID,
    service: CustomerProvisioningService = Depends(get_customer_provisioning_service),
):
    payload = await service.generate_wireguard(customer_id)
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )

"""FastAPI routes for the Network Device (NAC) domain: device registration
CRUD plus the admin-assessed compliance-status workflow.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``network_device.*`` permission key (see
``app.domains.rbac.seed`` -- ``PermissionModule.NETWORK_DEVICE``) and
resolves ``CurrentOrganization``, passed through to
``NetworkDeviceService`` as ``requesting_organization_id``.

**Route ordering matters.** ``GET /network-devices`` is registered before
``GET /network-devices/{device_id}`` so Starlette's first-match-wins
routing resolves the literal path first, mirroring the same discipline
``app.domains.dhcp.router`` already follows.
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

from .constants import ComplianceStatus
from .dependencies import get_network_device_service
from .models import NetworkDevice
from .schemas import (
    MessageResponse,
    NetworkDeviceComplianceStatusRequest,
    NetworkDeviceListResponse,
    NetworkDeviceRegisterRequest,
    NetworkDeviceResponse,
    NetworkDeviceUpdateRequest,
)
from .service import NetworkDeviceService

router = APIRouter(prefix="/network-devices", tags=["Network Device (NAC)"])


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


def _device_response(device: NetworkDevice) -> NetworkDeviceResponse:
    return NetworkDeviceResponse(
        id=str(device.id),
        organization_id=str(device.organization_id),
        location_id=str(device.location_id),
        router_id=str(device.router_id) if device.router_id else None,
        mac_address=device.mac_address,
        vendor=device.vendor,
        device_type=device.device_type,
        compliance_status=device.compliance_status,
        compliance_notes=device.compliance_notes,
        last_reviewed_at=device.last_reviewed_at,
        comment=device.comment,
        is_active=device.is_active,
        created_at=device.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[NetworkDeviceResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("network_device.create"))],
)
async def register_network_device(
    request: Request,
    payload: NetworkDeviceRegisterRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDeviceService = Depends(get_network_device_service),
):
    device = await service.register_device(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        location_id=uuid.UUID(payload.location_id),
        router_id=uuid.UUID(payload.router_id) if payload.router_id else None,
        mac_address=payload.mac_address,
        vendor=payload.vendor,
        device_type=payload.device_type,
        comment=payload.comment,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Network device registered",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[NetworkDeviceListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_device.read"))],
)
async def list_network_devices(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    compliance_status: ComplianceStatus | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDeviceService = Depends(get_network_device_service),
):
    devices, meta = await service.list_devices(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        compliance_status=compliance_status,
        page=page,
        page_size=page_size,
    )
    payload = NetworkDeviceListResponse(
        items=[_device_response(device) for device in devices],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Network devices retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{device_id}",
    response_model=ApiResponse[NetworkDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_device.read"))],
)
async def get_network_device(
    request: Request,
    device_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDeviceService = Depends(get_network_device_service),
):
    device = await service.get_device(
        device_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Network device retrieved",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{device_id}",
    response_model=ApiResponse[NetworkDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_device.update"))],
)
async def update_network_device(
    request: Request,
    device_id: uuid.UUID,
    payload: NetworkDeviceUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDeviceService = Depends(get_network_device_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "router_id" in fields:
        fields["router_id"] = uuid.UUID(fields["router_id"])
    device = await service.update_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Network device updated",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{device_id}/compliance-status",
    response_model=ApiResponse[NetworkDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_device.manage"))],
)
async def set_network_device_compliance_status(
    request: Request,
    device_id: uuid.UUID,
    payload: NetworkDeviceComplianceStatusRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDeviceService = Depends(get_network_device_service),
):
    device = await service.set_compliance_status(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        compliance_status=payload.compliance_status,
        compliance_notes=payload.compliance_notes,
    )
    return build_response(
        success=True,
        message="Network device compliance status updated",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{device_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_device.delete"))],
)
async def delete_network_device(
    request: Request,
    device_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDeviceService = Depends(get_network_device_service),
):
    await service.delete_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Network device deleted",
        data=MessageResponse(message="Network device deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

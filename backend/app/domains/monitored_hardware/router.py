"""FastAPI routes for the Monitored Hardware domain: register/list/delete
a venue's own network hardware.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
new ``monitored_hardware.*`` permission keys (see
``app.domains.rbac.seed`` -- ``PermissionModule.MONITORED_HARDWARE``) and
resolves ``CurrentOrganization``, passed through to
``MonitoredHardwareService`` as ``requesting_organization_id``.

**Route ordering matters.** ``GET /monitored-hardware`` is registered
before ``GET /monitored-hardware/{device_id}`` so Starlette's
first-match-wins routing resolves the literal path first, mirroring
``app.domains.network_device.router``'s identical discipline.
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

from .dependencies import get_monitored_hardware_service
from .schemas import (
    MessageResponse,
    MonitoredHardwareListResponse,
    MonitoredHardwareRegisterRequest,
    MonitoredHardwareResponse,
)
from .service import HardwareWithStatus, MonitoredHardwareService

router = APIRouter(prefix="/monitored-hardware", tags=["Monitored Hardware"])


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


def _device_response(item: HardwareWithStatus) -> MonitoredHardwareResponse:
    device = item.device
    return MonitoredHardwareResponse(
        id=str(device.id),
        organization_id=str(device.organization_id),
        location_id=str(device.location_id),
        router_id=str(device.router_id) if device.router_id else None,
        name=device.name,
        mac_address=device.mac_address,
        device_type=device.device_type,
        floor=device.floor,
        status=item.status.value,
        last_seen_at=item.last_seen_at,
        created_at=device.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[MonitoredHardwareResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("monitored_hardware.create"))],
)
async def register_monitored_hardware(
    request: Request,
    payload: MonitoredHardwareRegisterRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MonitoredHardwareService = Depends(get_monitored_hardware_service),
):
    device = await service.register_device(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        location_id=uuid.UUID(payload.location_id),
        router_id=uuid.UUID(payload.router_id) if payload.router_id else None,
        name=payload.name,
        mac_address=payload.mac_address,
        device_type=payload.device_type,
        floor=payload.floor,
    )
    item = await service.with_status(device)
    return build_response(
        success=True,
        message="Monitored hardware registered",
        data=_device_response(item).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[MonitoredHardwareListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitored_hardware.read"))],
)
async def list_monitored_hardware(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MonitoredHardwareService = Depends(get_monitored_hardware_service),
):
    items, meta = await service.list_devices(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    payload = MonitoredHardwareListResponse(
        items=[_device_response(item) for item in items],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Monitored hardware retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{device_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitored_hardware.delete"))],
)
async def delete_monitored_hardware(
    request: Request,
    device_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MonitoredHardwareService = Depends(get_monitored_hardware_service),
):
    await service.delete_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Monitored hardware deleted",
        data=MessageResponse(message="Monitored hardware deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

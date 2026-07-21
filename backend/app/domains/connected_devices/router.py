"""FastAPI routes for the Connected Device Management domain: read-model
listing, admin actions (comment/delete/disconnect/refresh/block/unblock/
whitelist), and a manual per-router sync trigger.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``connected_devices.*`` permission key (see
``app.domains.rbac.seed`` -- ``PermissionModule.CONNECTED_DEVICES``) and
resolves ``CurrentOrganization`` (``X-Organization-Id``), passed through
to ``ConnectedDeviceService`` as ``requesting_organization_id`` -- the
same tenant-scoping posture every other domain's router already
enforces.

**Route ordering matters.** ``GET /connected-devices`` (list) is
registered before ``GET /connected-devices/{device_id}`` so Starlette's
first-match-wins routing resolves the literal path first, mirroring the
same discipline every other domain's router already follows.
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

from .dependencies import get_connected_device_service
from .models import ConnectedDevice
from .schemas import (
    ConnectedDeviceAccessActionRequest,
    ConnectedDeviceCommentRequest,
    ConnectedDeviceListResponse,
    ConnectedDeviceResponse,
    DeviceSyncSummaryResponse,
    MessageResponse,
)
from .service import ConnectedDeviceService

router = APIRouter(prefix="/connected-devices", tags=["Connected Device Management"])


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


def _device_response(device: ConnectedDevice) -> ConnectedDeviceResponse:
    return ConnectedDeviceResponse(
        id=str(device.id),
        router_id=str(device.router_id),
        organization_id=str(device.organization_id),
        location_id=str(device.location_id),
        mac_address=device.mac_address,
        ip_address=device.ip_address,
        hostname=device.hostname,
        vendor=device.vendor,
        connection_type=device.connection_type,
        interface=device.interface,
        signal_strength_dbm=device.signal_strength_dbm,
        is_active=device.is_active,
        connected_at=device.connected_at,
        last_seen_at=device.last_seen_at,
        comment=device.comment,
        guest_id=str(device.guest_id) if device.guest_id else None,
        guest_session_id=str(device.guest_session_id)
        if device.guest_session_id
        else None,
        created_at=device.created_at,
    )


@router.get(
    "",
    response_model=ApiResponse[ConnectedDeviceListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.read"))],
)
async def list_connected_devices(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    devices, meta = await service.list_devices(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )
    payload = ConnectedDeviceListResponse(
        items=[_device_response(device) for device in devices],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Connected devices retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/sync/{router_id}",
    response_model=ApiResponse[DeviceSyncSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.execute"))],
)
async def sync_connected_devices(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    summary = await service.sync_router(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Connected devices synced",
        data=DeviceSyncSummaryResponse(
            discovered=summary.discovered,
            updated=summary.updated,
            disconnected=summary.disconnected,
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{device_id}",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.read"))],
)
async def get_connected_device(
    request: Request,
    device_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.get_device(
        device_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Connected device retrieved",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{device_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.delete"))],
)
async def delete_connected_device(
    request: Request,
    device_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    await service.delete_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Connected device deleted",
        data=MessageResponse(message="Connected device deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{device_id}/comment",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.update"))],
)
async def add_connected_device_comment(
    request: Request,
    device_id: uuid.UUID,
    payload: ConnectedDeviceCommentRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.add_comment(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        comment=payload.comment,
    )
    return build_response(
        success=True,
        message="Comment added",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{device_id}/disconnect",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.execute"))],
)
async def disconnect_connected_device(
    request: Request,
    device_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.disconnect_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Device disconnected",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{device_id}/refresh",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.execute"))],
)
async def refresh_connected_device(
    request: Request,
    device_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.refresh_device(
        device_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Device refreshed",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{device_id}/block",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.execute"))],
)
async def block_connected_device(
    request: Request,
    device_id: uuid.UUID,
    payload: ConnectedDeviceAccessActionRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.block_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Device blocked",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{device_id}/unblock",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.execute"))],
)
async def unblock_connected_device(
    request: Request,
    device_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.unblock_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Device unblocked",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{device_id}/whitelist",
    response_model=ApiResponse[ConnectedDeviceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("connected_devices.execute"))],
)
async def whitelist_connected_device(
    request: Request,
    device_id: uuid.UUID,
    payload: ConnectedDeviceAccessActionRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ConnectedDeviceService = Depends(get_connected_device_service),
):
    device = await service.whitelist_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Device whitelisted",
        data=_device_response(device).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

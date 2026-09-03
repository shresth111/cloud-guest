"""FastAPI routes for the DHCP Pool Management domain: per-router DHCP
pool CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``dhcp.*`` permission key (see ``app.domains.rbac.seed`` --
``PermissionModule.DHCP``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``DhcpService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /dhcp-pools`` is registered before
``GET /dhcp-pools/{pool_id}`` so Starlette's first-match-wins routing
resolves the literal path first, mirroring the same discipline
``app.domains.vlan.router`` already follows.
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

from .dependencies import get_dhcp_service
from .models import DhcpPool
from .schemas import (
    DhcpPoolCreateRequest,
    DhcpPoolListResponse,
    DhcpPoolResponse,
    DhcpPoolUpdateRequest,
    MessageResponse,
)
from .service import DhcpService

router = APIRouter(prefix="/dhcp-pools", tags=["DHCP Pool Management"])


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


def _pool_response(pool: DhcpPool) -> DhcpPoolResponse:
    return DhcpPoolResponse(
        id=str(pool.id),
        router_id=str(pool.router_id),
        organization_id=str(pool.organization_id),
        location_id=str(pool.location_id),
        name=pool.name,
        interface=pool.interface,
        address_range_start=pool.address_range_start,
        address_range_end=pool.address_range_end,
        gateway_ip_address=pool.gateway_ip_address,
        dns_primary=pool.dns_primary,
        dns_secondary=pool.dns_secondary,
        lease_time_seconds=pool.lease_time_seconds,
        is_enabled=pool.is_enabled,
        device_push_status=pool.device_push_status,
        device_push_error=pool.device_push_error,
        device_pushed_at=pool.device_pushed_at,
        created_at=pool.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[DhcpPoolResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("dhcp.create"))],
)
async def create_dhcp_pool(
    request: Request,
    payload: DhcpPoolCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DhcpService = Depends(get_dhcp_service),
):
    pool = await service.create_pool(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        address_range_start=payload.address_range_start,
        address_range_end=payload.address_range_end,
        interface=payload.interface,
        gateway_ip_address=payload.gateway_ip_address,
        dns_primary=payload.dns_primary,
        dns_secondary=payload.dns_secondary,
        lease_time_seconds=payload.lease_time_seconds,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="DHCP pool created",
        data=_pool_response(pool).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[DhcpPoolListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dhcp.read"))],
)
async def list_dhcp_pools(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DhcpService = Depends(get_dhcp_service),
):
    pools, meta = await service.list_pools(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = DhcpPoolListResponse(
        items=[_pool_response(pool) for pool in pools], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="DHCP pools retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{pool_id}",
    response_model=ApiResponse[DhcpPoolResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dhcp.read"))],
)
async def get_dhcp_pool(
    request: Request,
    pool_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DhcpService = Depends(get_dhcp_service),
):
    pool = await service.get_pool(
        pool_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="DHCP pool retrieved",
        data=_pool_response(pool).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{pool_id}",
    response_model=ApiResponse[DhcpPoolResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dhcp.update"))],
)
async def update_dhcp_pool(
    request: Request,
    pool_id: uuid.UUID,
    payload: DhcpPoolUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DhcpService = Depends(get_dhcp_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    pool = await service.update_pool(
        pool_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="DHCP pool updated",
        data=_pool_response(pool).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{pool_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dhcp.delete"))],
)
async def delete_dhcp_pool(
    request: Request,
    pool_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DhcpService = Depends(get_dhcp_service),
):
    await service.delete_pool(
        pool_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="DHCP pool deleted",
        data=MessageResponse(message="DHCP pool deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{pool_id}/push",
    response_model=ApiResponse[DhcpPoolResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dhcp.execute"))],
)
async def push_dhcp_pool(
    request: Request,
    pool_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DhcpService = Depends(get_dhcp_service),
):
    """Realizes this DHCP pool on its own router over the RouterOS API.

    Gated by ``dhcp.execute``, not ``dhcp.update``: editing a row and
    reaching into a live router are different privileges. That action is
    new -- ``app.domains.rbac.seed`` must be re-run on deploy or every
    operator gets a 403 here. (That is not hypothetical: the identical
    ``vlan.execute`` action shipped without the seed being run, and the
    Apply button 403'd against a working adapter until it was.)

    **There is no try/except in this handler, deliberately.** Every failure
    path raises a ``DhcpError`` carrying its own status code (502 for a
    device connection or operation failure, 409/400/403/404 for the rest),
    and the app-wide ``CloudGuestError`` handler turns it into a real
    non-2xx.

    Returning ``200 {"success": false}`` instead would be invisible: the
    frontend's response interceptor unwraps ``response.data.data`` and never
    reads ``success``, so such a response reaches the UI as a success. The
    honesty has to live in the status code.
    """
    pool = await service.push_pool_to_device(
        pool_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="DHCP pool pushed to device",
        data=_pool_response(pool).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

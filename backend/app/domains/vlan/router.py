"""FastAPI routes for the VLAN Management domain: per-router VLAN CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``vlan.*`` permission key (see ``app.domains.rbac.seed`` --
``PermissionModule.VLAN``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``VlanService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /vlans`` is registered before
``GET /vlans/{vlan_pk}`` so Starlette's first-match-wins routing resolves
the literal path first, mirroring the same discipline
``app.domains.isp_routing.router`` already follows.
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

from .dependencies import get_vlan_service
from .models import Vlan
from .schemas import (
    MessageResponse,
    VlanCreateRequest,
    VlanListResponse,
    VlanResponse,
    VlanUpdateRequest,
)
from .service import VlanService

router = APIRouter(prefix="/vlans", tags=["VLAN Management"])


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


def _vlan_response(vlan: Vlan) -> VlanResponse:
    return VlanResponse(
        id=str(vlan.id),
        router_id=str(vlan.router_id),
        organization_id=str(vlan.organization_id),
        location_id=str(vlan.location_id),
        vlan_id=vlan.vlan_id,
        name=vlan.name,
        gateway_ip_address=vlan.gateway_ip_address,
        cidr=vlan.cidr,
        interface=vlan.interface,
        description=vlan.description,
        is_enabled=vlan.is_enabled,
        created_at=vlan.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[VlanResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("vlan.create"))],
)
async def create_vlan(
    request: Request,
    payload: VlanCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    vlan = await service.create_vlan(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        vlan_id=payload.vlan_id,
        name=payload.name,
        gateway_ip_address=payload.gateway_ip_address,
        cidr=payload.cidr,
        interface=payload.interface,
        description=payload.description,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="VLAN created",
        data=_vlan_response(vlan).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[VlanListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("vlan.read"))],
)
async def list_vlans(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    vlans, meta = await service.list_vlans(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = VlanListResponse(
        items=[_vlan_response(vlan) for vlan in vlans], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="VLANs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{vlan_pk}",
    response_model=ApiResponse[VlanResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("vlan.read"))],
)
async def get_vlan(
    request: Request,
    vlan_pk: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    vlan = await service.get_vlan(
        vlan_pk, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="VLAN retrieved",
        data=_vlan_response(vlan).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{vlan_pk}",
    response_model=ApiResponse[VlanResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("vlan.update"))],
)
async def update_vlan(
    request: Request,
    vlan_pk: uuid.UUID,
    payload: VlanUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    vlan = await service.update_vlan(
        vlan_pk,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="VLAN updated",
        data=_vlan_response(vlan).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{vlan_pk}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("vlan.delete"))],
)
async def delete_vlan(
    request: Request,
    vlan_pk: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    await service.delete_vlan(
        vlan_pk,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="VLAN deleted",
        data=MessageResponse(message="VLAN deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

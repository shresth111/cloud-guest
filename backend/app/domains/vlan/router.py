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
    VlanDeviceInterfaceResponse,
    VlanDeviceInterfacesResponse,
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


def _vlan_response(
    vlan: Vlan, *, has_dhcp: bool | None = None
) -> VlanResponse:
    """``has_dhcp`` is passed only where it was computed. Left ``None``
    elsewhere rather than defaulted to ``False``: "we did not look" and
    "nothing hands out addresses here" are different answers, and guessing
    the second would put a warning on rows that do not deserve one."""
    return VlanResponse(
        has_dhcp=has_dhcp,
        id=str(vlan.id),
        router_id=str(vlan.router_id),
        organization_id=str(vlan.organization_id),
        location_id=str(vlan.location_id),
        vlan_id=vlan.vlan_id,
        name=vlan.name,
        gateway_ip_address=vlan.gateway_ip_address,
        cidr=vlan.cidr,
        interface=vlan.interface,
        port_mode=vlan.port_mode,
        enable_hotspot=vlan.enable_hotspot,
        nat_enabled=vlan.nat_enabled,
        description=vlan.description,
        is_enabled=vlan.is_enabled,
        confirm_takes_port=vlan.confirm_takes_port,
        device_push_status=vlan.device_push_status,
        device_push_error=vlan.device_push_error,
        device_pushed_at=vlan.device_pushed_at,
        mikrotik_interface_name=vlan.mikrotik_interface_name,
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
        port_mode=payload.port_mode,
        enable_hotspot=payload.enable_hotspot,
        nat_enabled=payload.nat_enabled,
        description=payload.description,
        is_enabled=payload.is_enabled,
        confirm_takes_port=payload.confirm_takes_port,
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
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    vlans, meta = await service.list_vlans(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    # One DHCP lookup per distinct router, not one per VLAN: the list is
    # usually all one router's VLANs, and asking per row would turn a page
    # render into N queries for an answer that is the same every time.
    dhcp_by_router: dict[uuid.UUID, set[str]] = {}
    for vlan in vlans:
        if vlan.router_id not in dhcp_by_router:
            dhcp_by_router[vlan.router_id] = await service.dhcp_interfaces_for_router(
                vlan.router_id
            )
    payload = VlanListResponse(
        items=[
            _vlan_response(
                vlan,
                has_dhcp=service.vlan_has_dhcp(vlan, dhcp_by_router[vlan.router_id]),
            )
            for vlan in vlans
        ],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="VLANs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/device-interfaces",
    response_model=ApiResponse[VlanDeviceInterfacesResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("vlan.read"))],
)
async def list_device_interfaces(
    request: Request,
    router_id: uuid.UUID = Query(...),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    """The router's real interfaces, backing this domain's own VLAN form.

    **Registered before ``GET /{vlan_pk}`` deliberately.** Starlette
    resolves first-match-wins, so below it this literal path would be
    handed to a ``uuid.UUID`` parser and answer 422 forever.

    **Gated on ``vlan.read``, not ``routers.manage``.** This is a
    customer-facing form field. ``routers.manage`` folds out of a FULL
    grant only -- an Organization *Admin*, a Location Manager and every
    OPERATE-level role hold ``vlan.read`` and would 403 here on the exact
    screen they are allowed to use. Reading a router's interface names is
    also strictly less than what ``vlan.read`` already implies: the VLAN
    rows it returns name those same interfaces.

    **Deliberately not ``GET /routers/{id}/device-interfaces``.** That one
    filters out every interface already bound to an ``/ip dhcp-server``,
    which on a real router removes ``bridge`` -- confirmed on the lab
    device, where ``bridge`` was simply absent from its output. It is the
    right filter for a DHCP picker and the wrong one here, because
    ``bridge`` is what most VLAN trunks hang off.

    A router with no stored credentials, or one that does not answer,
    returns an empty list and a message saying which -- not a 500, and not
    a ``200 {"success": false}`` the frontend interceptor would discard
    along with the explanation. The push endpoint is where unreachability
    is fatal, and it is.
    """
    interfaces, message = await service.list_device_interfaces(
        router_id, requesting_organization_id=requesting_organization_id
    )
    payload = VlanDeviceInterfacesResponse(
        interfaces=[
            VlanDeviceInterfaceResponse(
                name=i.name,
                type=i.type,
                running=i.running,
                disabled=i.disabled,
                bridge=i.bridge,
                is_bridge_port=i.is_bridge_port,
                has_ip_address=i.has_ip_address,
            )
            for i in interfaces
        ]
    )
    return build_response(
        success=True,
        message=message,
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


@router.post(
    "/{vlan_pk}/push",
    response_model=ApiResponse[VlanResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("vlan.execute"))],
)
async def push_vlan(
    request: Request,
    vlan_pk: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VlanService = Depends(get_vlan_service),
):
    """Realizes this VLAN on its own router over the RouterOS API.

    Gated by ``vlan.execute``, not ``vlan.update``: editing a row and
    reaching into a live router are different privileges. That action is
    new -- ``app.domains.rbac.seed`` must be re-run on deploy or every
    operator gets a 403 here.

    **There is no try/except in this handler, deliberately.** Every failure
    path raises a ``VlanError`` carrying its own status code (502 for a
    device connection or operation failure, 409/400/403/404 for the rest),
    and the app-wide ``CloudGuestError`` handler turns it into a real
    non-2xx.

    One of those 409s is worth knowing about from the UI side: an
    access-mode VLAN whose port is currently in a bridge is **refused**
    until ``confirm_takes_port`` is set on the row (via create or update).
    Taking that port out of its bridge cuts off whatever is behind it, so
    it has to be asked for rather than warned about.

    Returning ``200 {"success": false}`` instead would be invisible: the
    frontend's response interceptor unwraps ``response.data.data`` and never
    reads ``success``, so such a response reaches the UI as a success. The
    honesty has to live in the status code -- which is exactly the lesson of
    ``POST /network-config/routers/{id}/push``, which returns 202
    ``success: true`` without reading ``job.status``.
    """
    vlan = await service.push_vlan_to_device(
        vlan_pk,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="VLAN pushed to device",
        data=_vlan_response(vlan).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

"""FastAPI routes for the ISP Management domain: WAN/ISP link CRUD, a
manual on-demand health check, health-check history (a read-model, plus
the computed availability percentage -- see ``service.py``'s
``compute_availability_percentage``), and manual failover/failback
triggers for admins who don't want to wait for the next scheduled sweep
tick.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
new ``isp.*`` permission keys (see ``app.domains.rbac.seed`` --
``PermissionModule.ISP``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``IspService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /isp/links`` is registered before
``GET /isp/links/{link_id}`` so Starlette's first-match-wins routing
resolves the literal path first, mirroring the same discipline
``app.domains.queue_management.router`` already follows.
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

from .constants import IspLinkRole
from .dependencies import get_isp_service
from .models import IspHealthCheck, IspLink
from .schemas import (
    IspFailoverRequest,
    IspHealthCheckListResponse,
    IspHealthCheckResponse,
    IspLinkCreateRequest,
    IspLinkListResponse,
    IspLinkResponse,
    IspLinkUpdateRequest,
    MessageResponse,
)
from .service import IspService

router = APIRouter(prefix="/isp", tags=["ISP Management"])


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


# ============================================================================
# Response builders
# ============================================================================


def _link_response(link: IspLink) -> IspLinkResponse:
    return IspLinkResponse(
        id=str(link.id),
        router_id=str(link.router_id),
        organization_id=str(link.organization_id),
        location_id=str(link.location_id),
        provider_name=link.provider_name,
        link_type=link.link_type,
        role=link.role,
        is_active_uplink=link.is_active_uplink,
        auto_failback=link.auto_failback,
        is_enabled=link.is_enabled,
        priority=link.priority,
        interface=link.interface,
        gateway_ip_address=link.gateway_ip_address,
        dns_primary=link.dns_primary,
        dns_secondary=link.dns_secondary,
        download_bandwidth_mbps=link.download_bandwidth_mbps,
        upload_bandwidth_mbps=link.upload_bandwidth_mbps,
        health_status=link.health_status,
        latency_ms=link.latency_ms,
        packet_loss_percentage=link.packet_loss_percentage,
        last_checked_at=link.last_checked_at,
        consecutive_unhealthy_count=link.consecutive_unhealthy_count,
        created_at=link.created_at,
    )


def _health_check_response(check: IspHealthCheck) -> IspHealthCheckResponse:
    return IspHealthCheckResponse(
        id=str(check.id),
        isp_link_id=str(check.isp_link_id),
        checked_at=check.checked_at,
        status=check.status,
        latency_ms=check.latency_ms,
        packet_loss_percentage=check.packet_loss_percentage,
        error_message=check.error_message,
    )


# ============================================================================
# ISP links: CRUD
# ============================================================================


@router.post(
    "/links",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("isp.create"))],
)
async def create_isp_link(
    request: Request,
    payload: IspLinkCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    link = await service.create_link(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        provider_name=payload.provider_name,
        link_type=payload.link_type,
        role=IspLinkRole(payload.role),
        priority=payload.priority,
        interface=payload.interface,
        gateway_ip_address=payload.gateway_ip_address,
        dns_primary=payload.dns_primary,
        dns_secondary=payload.dns_secondary,
        download_bandwidth_mbps=payload.download_bandwidth_mbps,
        upload_bandwidth_mbps=payload.upload_bandwidth_mbps,
        auto_failback=payload.auto_failback,
    )
    return build_response(
        success=True,
        message="ISP link created",
        data=_link_response(link).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/links",
    response_model=ApiResponse[IspLinkListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.read"))],
)
async def list_isp_links(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    links, meta = await service.list_links(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = IspLinkListResponse(
        items=[_link_response(link) for link in links], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="ISP links retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/links/{link_id}",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.read"))],
)
async def get_isp_link(
    request: Request,
    link_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    link = await service.get_link(
        link_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="ISP link retrieved",
        data=_link_response(link).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/links/{link_id}",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.update"))],
)
async def update_isp_link(
    request: Request,
    link_id: uuid.UUID,
    payload: IspLinkUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    link = await service.update_link(
        link_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="ISP link updated",
        data=_link_response(link).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/links/{link_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.delete"))],
)
async def delete_isp_link(
    request: Request,
    link_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    await service.delete_link(
        link_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="ISP link deleted",
        data=MessageResponse(message="ISP link deleted").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Health checks: manual trigger + history
# ============================================================================


@router.post(
    "/links/{link_id}/check-health",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.execute"))],
)
async def check_isp_link_health(
    request: Request,
    link_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    link = await service.check_link_health(
        link_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="ISP link health check completed",
        data=_link_response(link).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/links/{link_id}/health-checks",
    response_model=ApiResponse[IspHealthCheckListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.read"))],
)
async def list_isp_link_health_checks(
    request: Request,
    link_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    checks, meta = await service.list_health_checks(
        link_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    availability_percentage = service.compute_availability_percentage(checks)
    payload = IspHealthCheckListResponse(
        items=[_health_check_response(check) for check in checks],
        availability_percentage=availability_percentage,
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="ISP link health checks retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Failover / failback (manual trigger)
# ============================================================================


@router.post(
    "/routers/{router_id}/failover",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.execute"))],
)
async def trigger_isp_failover(
    request: Request,
    router_id: uuid.UUID,
    payload: IspFailoverRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    link = await service.trigger_failover(
        router_id,
        actor_user_id=uuid.UUID(actor.id),
        reason=payload.reason,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="ISP failover triggered",
        data=_link_response(link).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/failback",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.execute"))],
)
async def trigger_isp_failback(
    request: Request,
    router_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    link = await service.trigger_failback(
        router_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="ISP failback triggered",
        data=_link_response(link).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

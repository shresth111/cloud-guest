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
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import HealthStatus, IspLinkRole, WanRoutingMode
from .dependencies import get_isp_service
from .models import IspHealthCheck, IspLink
from .schemas import (
    IspFailoverRequest,
    IspHealthCheckBucketResponse,
    IspHealthCheckListResponse,
    IspHealthCheckResponse,
    IspHealthCheckSummaryResponse,
    IspLinkCreateRequest,
    IspLinkListResponse,
    IspLinkManualStatusRequest,
    IspLinkResponse,
    IspLinkUpdateRequest,
    IspSpeedTestResponse,
    MessageResponse,
    WanRoutingModeRequest,
    WanRoutingModeResponse,
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


def _link_response(
    link: IspLink, *, unhealthy_since: datetime | None = None
) -> IspLinkResponse:
    return IspLinkResponse(
        id=str(link.id),
        router_id=str(link.router_id),
        organization_id=str(link.organization_id),
        location_id=str(link.location_id),
        provider_name=link.provider_name,
        link_type=link.link_type,
        connection_mode=link.connection_mode,
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
        load_balance_weight=link.load_balance_weight,
        health_status=link.health_status,
        health_status_source=link.health_status_source,
        unhealthy_since=unhealthy_since,
        latency_ms=link.latency_ms,
        packet_loss_percentage=link.packet_loss_percentage,
        current_download_mbps=link.current_download_mbps,
        current_upload_mbps=link.current_upload_mbps,
        last_checked_at=link.last_checked_at,
        consecutive_unhealthy_count=link.consecutive_unhealthy_count,
        created_at=link.created_at,
    )


def _speed_test_response(outcome) -> IspSpeedTestResponse:  # noqa: ANN001
    return IspSpeedTestResponse(
        isp_link_id=str(outcome.isp_link_id),
        tested_at=outcome.tested_at,
        download_mbps=outcome.download_mbps,
        upload_mbps=outcome.upload_mbps,
        latency_ms=outcome.latency_ms,
        packet_loss_percentage=outcome.packet_loss_percentage,
        downloaded_bytes=outcome.downloaded_bytes,
        duration_seconds=outcome.duration_seconds,
    )


def _health_check_response(check: IspHealthCheck) -> IspHealthCheckResponse:
    return IspHealthCheckResponse(
        id=str(check.id),
        isp_link_id=str(check.isp_link_id),
        checked_at=check.checked_at,
        status=check.status,
        source=check.source,
        latency_ms=check.latency_ms,
        packet_loss_percentage=check.packet_loss_percentage,
        error_message=check.error_message,
        download_mbps=check.download_mbps,
        upload_mbps=check.upload_mbps,
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
        connection_mode=payload.connection_mode,
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
    items = [
        _link_response(link, unhealthy_since=await service.compute_unhealthy_since(link))
        for link in links
    ]
    payload = IspLinkListResponse(items=items, **_pagination_fields(meta))
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
    unhealthy_since = await service.compute_unhealthy_since(link)
    return build_response(
        success=True,
        message="ISP link retrieved",
        data=_link_response(link, unhealthy_since=unhealthy_since).model_dump(),
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
    unhealthy_since = await service.compute_unhealthy_since(link)
    return build_response(
        success=True,
        message="ISP link updated",
        data=_link_response(link, unhealthy_since=unhealthy_since).model_dump(),
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


@router.put(
    "/routers/{router_id}/wan-routing-mode",
    response_model=ApiResponse[WanRoutingModeResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.update"))],
)
async def set_wan_routing_mode(
    request: Request,
    router_id: uuid.UUID,
    payload: WanRoutingModeRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    updated_router = await service.set_wan_routing_mode(
        router_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        mode=WanRoutingMode(payload.mode),
    )
    return build_response(
        success=True,
        message="WAN routing mode updated",
        data=WanRoutingModeResponse(
            router_id=str(updated_router.id),
            wan_routing_mode=updated_router.wan_routing_mode,
        ).model_dump(),
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
    unhealthy_since = await service.compute_unhealthy_since(link)
    return build_response(
        success=True,
        message="ISP link health check completed",
        data=_link_response(link, unhealthy_since=unhealthy_since).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/links/{link_id}/speed-test",
    response_model=ApiResponse[IspSpeedTestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.execute"))],
)
async def run_isp_link_speed_test(
    request: Request,
    link_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    """On-demand "Run Speed Test" -- a real, slow (multi-second) action:
    issues a genuine RouterOS download against the router's own real WAN
    uplink, plus a real ping for latency. Gated by ``isp.execute`` (the
    same permission ``check-health``/failover already require) since this
    is a real, on-demand device action, not a read. See
    ``IspService.run_speed_test``'s own docstring for why this is never
    persisted into the routine health-check history and why no
    ``upload_mbps`` is ever fabricated."""
    outcome = await service.run_speed_test(
        link_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="ISP link speed test completed",
        data=_speed_test_response(outcome).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/links/{link_id}/status",
    response_model=ApiResponse[IspLinkResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.update"))],
)
async def set_isp_link_manual_status(
    request: Request,
    link_id: uuid.UUID,
    payload: IspLinkManualStatusRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    """An admin's own manual override of a link's current status --
    ``isp.update`` (the same permission ``PUT /links/{link_id}`` already
    requires) since this is a state change to the link's own row, not a
    new class of action. Never opens a device connection -- see
    ``IspService.set_manual_health_status``'s own docstring."""
    link = await service.set_manual_health_status(
        link_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        health_status=HealthStatus(payload.health_status),
        reason=payload.reason,
    )
    unhealthy_since = await service.compute_unhealthy_since(link)
    return build_response(
        success=True,
        message="ISP link status updated",
        data=_link_response(link, unhealthy_since=unhealthy_since).model_dump(),
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
    # Optional date-range filter -- both default to None (no restriction),
    # matching every existing caller's current "just the most recent
    # page" behavior exactly. Same param names/semantics as
    # ``app.domains.monitoring.router``'s own ``start_date``/``end_date``
    # on ``GET /events``.
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    checks, meta = await service.list_health_checks(
        link_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        start=start_date,
        end=end_date,
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


@router.get(
    "/links/{link_id}/health-checks/summary",
    response_model=ApiResponse[IspHealthCheckSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("isp.read"))],
)
async def get_isp_link_health_check_summary(
    request: Request,
    link_id: uuid.UUID,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: IspService = Depends(get_isp_service),
):
    """Backs the "Internet Connection" history dialog's uptime chart for
    its 7-day/30-day ranges -- SQL-side time-bucketed aggregation
    (``IspService.get_health_check_summary``), never individual rows, so
    a 30-day window at the sweep's real 60-second cadence (~43k rows per
    link) comes back as ~30 aggregated rows instead."""
    bucket_unit, buckets = await service.get_health_check_summary(
        link_id,
        requesting_organization_id=requesting_organization_id,
        start=start_date,
        end=end_date,
    )
    payload = IspHealthCheckSummaryResponse(
        bucket_unit=bucket_unit,
        start=start_date,
        end=end_date,
        buckets=[
            IspHealthCheckBucketResponse(
                bucket_start=b.bucket_start,
                total_checks=b.total_checks,
                healthy_count=b.healthy_count,
                degraded_count=b.degraded_count,
                unhealthy_count=b.unhealthy_count,
                uptime_percentage=b.uptime_percentage,
                avg_latency_ms=b.avg_latency_ms,
                avg_packet_loss_percentage=b.avg_packet_loss_percentage,
                avg_download_mbps=b.avg_download_mbps,
                avg_upload_mbps=b.avg_upload_mbps,
                max_download_mbps=b.max_download_mbps,
            )
            for b in buckets
        ],
    )
    return build_response(
        success=True,
        message="ISP link health check summary retrieved",
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
    unhealthy_since = await service.compute_unhealthy_since(link)
    return build_response(
        success=True,
        message="ISP failover triggered",
        data=_link_response(link, unhealthy_since=unhealthy_since).model_dump(),
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
    unhealthy_since = await service.compute_unhealthy_since(link)
    return build_response(
        success=True,
        message="ISP failback triggered",
        data=_link_response(link, unhealthy_since=unhealthy_since).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

"""FastAPI routes for the Network Diagnostics domain: trigger a real
``ping``/``traceroute`` against a router, and read its immutable
history.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``network_diagnostics.*`` permission key (see
``app.domains.rbac.seed`` -- ``PermissionModule.NETWORK_DIAGNOSTICS``)
and resolves ``CurrentOrganization`` (``X-Organization-Id``), passed
through to ``NetworkDiagnosticsService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /network-diagnostics/runs`` (list) is
registered before ``GET /network-diagnostics/runs/{run_id}`` so
Starlette's first-match-wins routing resolves the literal path first,
mirroring the same discipline every other domain's router already
follows.
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

from .dependencies import get_network_diagnostics_service
from .models import DiagnosticRun
from .schemas import (
    DiagnosticRunListResponse,
    DiagnosticRunResponse,
    PingRequest,
    TracerouteRequest,
)
from .service import NetworkDiagnosticsService

router = APIRouter(prefix="/network-diagnostics", tags=["Network Diagnostics"])


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


def _run_response(run: DiagnosticRun) -> DiagnosticRunResponse:
    return DiagnosticRunResponse(
        id=str(run.id),
        router_id=str(run.router_id),
        organization_id=str(run.organization_id),
        location_id=str(run.location_id),
        diagnostic_type=run.diagnostic_type,
        target=run.target,
        status=run.status,
        result=run.result,
        error_message=run.error_message,
        executed_by_user_id=(
            str(run.executed_by_user_id) if run.executed_by_user_id else None
        ),
        created_at=run.created_at,
    )


@router.post(
    "/routers/{router_id}/ping",
    response_model=ApiResponse[DiagnosticRunResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_diagnostics.execute"))],
)
async def ping_router(
    request: Request,
    router_id: uuid.UUID,
    payload: PingRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDiagnosticsService = Depends(get_network_diagnostics_service),
):
    run = await service.run_ping(
        router_id,
        target=payload.target,
        count=payload.count,
        timeout_seconds=payload.timeout_seconds,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Ping completed",
        data=_run_response(run).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/traceroute",
    response_model=ApiResponse[DiagnosticRunResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_diagnostics.execute"))],
)
async def traceroute_router(
    request: Request,
    router_id: uuid.UUID,
    payload: TracerouteRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDiagnosticsService = Depends(get_network_diagnostics_service),
):
    run = await service.run_traceroute(
        router_id,
        target=payload.target,
        max_hops=payload.max_hops,
        timeout_seconds=payload.timeout_seconds,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Traceroute completed",
        data=_run_response(run).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/runs",
    response_model=ApiResponse[DiagnosticRunListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_diagnostics.read"))],
)
async def list_diagnostic_runs(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDiagnosticsService = Depends(get_network_diagnostics_service),
):
    runs, meta = await service.list_runs(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = DiagnosticRunListResponse(
        items=[_run_response(run) for run in runs], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Diagnostic history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/runs/{run_id}",
    response_model=ApiResponse[DiagnosticRunResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_diagnostics.read"))],
)
async def get_diagnostic_run(
    request: Request,
    run_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkDiagnosticsService = Depends(get_network_diagnostics_service),
):
    run = await service.get_run(
        run_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Diagnostic run retrieved",
        data=_run_response(run).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

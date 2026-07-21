"""FastAPI routes for the Device Synchronization domain: trigger a
router-wide sync, and read its immutable history.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against a
brand-new ``device_sync.*`` permission key (see ``app.domains.rbac.seed``
-- ``PermissionModule.DEVICE_SYNC``) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``DeviceSyncService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /device-sync/runs`` (list) is
registered before ``GET /device-sync/runs/{run_id}`` so Starlette's
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

from .dependencies import get_device_sync_service
from .models import DeviceSyncRun
from .schemas import DeviceSyncRunListResponse, DeviceSyncRunResponse
from .service import DeviceSyncService

router = APIRouter(prefix="/device-sync", tags=["Device Synchronization"])


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


def _run_response(run: DeviceSyncRun) -> DeviceSyncRunResponse:
    return DeviceSyncRunResponse(
        id=str(run.id),
        router_id=str(run.router_id),
        organization_id=str(run.organization_id),
        location_id=str(run.location_id),
        status=run.status,
        component_results=run.component_results,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
    )


@router.post(
    "/routers/{router_id}/sync",
    response_model=ApiResponse[DeviceSyncRunResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("device_sync.execute"))],
)
async def sync_router(
    request: Request,
    router_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DeviceSyncService = Depends(get_device_sync_service),
):
    run = await service.sync_router(
        router_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Device sync completed",
        data=_run_response(run).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/runs",
    response_model=ApiResponse[DeviceSyncRunListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("device_sync.read"))],
)
async def list_device_sync_runs(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DeviceSyncService = Depends(get_device_sync_service),
):
    runs, meta = await service.list_runs(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = DeviceSyncRunListResponse(
        items=[_run_response(run) for run in runs], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Device sync history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/runs/{run_id}",
    response_model=ApiResponse[DeviceSyncRunResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("device_sync.read"))],
)
async def get_device_sync_run(
    request: Request,
    run_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DeviceSyncService = Depends(get_device_sync_service),
):
    run = await service.get_run(
        run_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Device sync run retrieved",
        data=_run_response(run).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

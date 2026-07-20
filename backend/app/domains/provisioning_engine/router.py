"""FastAPI routes for the Provisioning Engine domain: the end-to-end
automation orchestrator (create/start/retry/rollback/cancel a
:class:`~.models.ProvisionJob`, list/inspect jobs and history/timeline, and
three ad-hoc actions -- discover/validate/generate-configuration-preview --
usable independently of a job, e.g. for a dashboard's "test connection"
button before a real provision run is ever started).

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
``provisioning_engine.*`` permission keys (see ``app.domains.rbac.seed``)
and resolves ``CurrentOrganization`` (``X-Organization-Id``), passed through
to ``ProvisioningEngineService`` as ``requesting_organization_id`` -- the
same tenant-scoping posture every other domain's router already enforces.

**Route ordering matters.** ``GET /provision/jobs`` and
``GET /provision/history`` are registered *before*
``GET /provision/{job_id}`` so Starlette's first-match-wins routing resolves
them as their own literal paths rather than as ``job_id="jobs"``/
``job_id="history"`` -- mirrors the same discipline every other domain's
router already follows for a list route living alongside a by-id route.
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

from .constants import ProvisionJobStatus
from .dependencies import get_provisioning_engine_service
from .models import ProvisionJob
from .schemas import (
    DeviceDiscoveryResultResponse,
    MessageResponse,
    ProvisionCancelRequest,
    ProvisionConfigurationRequest,
    ProvisionConfigurationResponse,
    ProvisionDiscoverRequest,
    ProvisionJobCreateRequest,
    ProvisionJobListResponse,
    ProvisionJobResponse,
    ProvisionTimelineEntryResponse,
    ProvisionTimelineResponse,
    ProvisionValidateRequest,
)
from .service import ProvisioningEngineService, TimelineEntry

router = APIRouter(prefix="/provision", tags=["Provisioning Engine"])


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


def _job_response(job: ProvisionJob) -> ProvisionJobResponse:
    return ProvisionJobResponse(
        id=str(job.id),
        organization_id=str(job.organization_id),
        location_id=str(job.location_id),
        router_id=str(job.router_id),
        provision_template_id=str(job.provision_template_id)
        if job.provision_template_id
        else None,
        status=job.status,
        current_step=job.current_step,
        progress_percent=job.progress_percent,
        requested_by_user_id=str(job.requested_by_user_id)
        if job.requested_by_user_id
        else None,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        retry_count=job.retry_count,
        max_retries=job.max_retries,
        retry_of_job_id=str(job.retry_of_job_id) if job.retry_of_job_id else None,
        is_rollback=job.is_rollback,
        rollback_of_job_id=str(job.rollback_of_job_id)
        if job.rollback_of_job_id
        else None,
        applied_config_version_id=str(job.applied_config_version_id)
        if job.applied_config_version_id
        else None,
        created_at=job.created_at,
    )


def _timeline_entry_response(entry: TimelineEntry) -> ProvisionTimelineEntryResponse:
    return ProvisionTimelineEntryResponse(
        label=entry.label,
        occurred_at=entry.occurred_at,
        step_type=entry.step_type,
        status=entry.status,
        detail=entry.detail,
    )


# ============================================================================
# Jobs: create / list / history
# ============================================================================


@router.post(
    "",
    response_model=ApiResponse[ProvisionJobResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("provisioning_engine.create"))],
)
async def create_provision_job(
    request: Request,
    payload: ProvisionJobCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    job = await service.create_job(
        actor_user_id=uuid.UUID(user.id),
        router_id=uuid.UUID(payload.router_id),
        requesting_organization_id=requesting_organization_id,
        provision_template_id=uuid.UUID(payload.provision_template_id)
        if payload.provision_template_id
        else None,
        max_retries=payload.max_retries,
    )
    return build_response(
        success=True,
        message="Provision job created",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/jobs",
    response_model=ApiResponse[ProvisionJobListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.read"))],
)
async def list_provision_jobs(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    job_status: ProvisionJobStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    jobs, meta = await service.list_jobs(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        status=job_status,
        page=page,
        page_size=page_size,
    )
    payload = ProvisionJobListResponse(
        items=[_job_response(j) for j in jobs], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Provision jobs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/history",
    response_model=ApiResponse[ProvisionJobListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.read"))],
)
async def get_provision_history(
    request: Request,
    router_id: uuid.UUID = Query(...),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    jobs, meta = await service.get_history(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ProvisionJobListResponse(
        items=[_job_response(j) for j in jobs], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Provision history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Ad-hoc actions: discover / validate / configuration preview
# ============================================================================


@router.post(
    "/discover",
    response_model=ApiResponse[DeviceDiscoveryResultResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def discover_device(
    request: Request,
    payload: ProvisionDiscoverRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    result = await service.discover_device(
        router_id=uuid.UUID(payload.router_id),
        requesting_organization_id=requesting_organization_id,
    )
    data = DeviceDiscoveryResultResponse(
        vendor=result.vendor,
        model=result.model,
        serial_number=result.serial_number,
        firmware_version=result.firmware_version,
        cpu_load_percent=result.cpu_load_percent,
        free_memory_bytes=result.free_memory_bytes,
        total_memory_bytes=result.total_memory_bytes,
        uptime_seconds=result.uptime_seconds,
        interfaces=result.interfaces,
        mac_address=result.mac_address,
    )
    return build_response(
        success=True,
        message="Device discovery completed",
        data=data.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/validate",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def validate_device(
    request: Request,
    payload: ProvisionValidateRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    await service.validate_device(
        router_id=uuid.UUID(payload.router_id),
        requesting_organization_id=requesting_organization_id,
        provision_template_id=uuid.UUID(payload.provision_template_id)
        if payload.provision_template_id
        else None,
    )
    return build_response(
        success=True,
        message="Device validation passed",
        data=MessageResponse(message="Device validation passed").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/configuration",
    response_model=ApiResponse[ProvisionConfigurationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def generate_configuration_preview(
    request: Request,
    payload: ProvisionConfigurationRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    preview = await service.generate_configuration(
        router_id=uuid.UUID(payload.router_id),
        requesting_organization_id=requesting_organization_id,
        provision_template_id=uuid.UUID(payload.provision_template_id),
        actor_user_id=uuid.UUID(user.id),
    )
    data = ProvisionConfigurationResponse(
        rendered_content=preview.rendered_content, variables_used=preview.variables_used
    )
    return build_response(
        success=True,
        message="Configuration generated",
        data=data.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Job lifecycle: start / retry / rollback / cancel
# ============================================================================


@router.post(
    "/{job_id}/start",
    response_model=ApiResponse[ProvisionJobResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def start_provision_job(
    request: Request,
    job_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    job = await service.start_job(
        job_id=job_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Provision job queued",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{job_id}/retry",
    response_model=ApiResponse[ProvisionJobResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def retry_provision_job(
    request: Request,
    job_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    job = await service.retry_job(
        job_id=job_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Provision job retry queued",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{job_id}/rollback",
    response_model=ApiResponse[ProvisionJobResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def rollback_provision_job(
    request: Request,
    job_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    job = await service.rollback_job(
        job_id=job_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Provision job rollback queued",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{job_id}/cancel",
    response_model=ApiResponse[ProvisionJobResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.execute"))],
)
async def cancel_provision_job(
    request: Request,
    job_id: uuid.UUID,
    payload: ProvisionCancelRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    job = await service.cancel_job(
        job_id=job_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Provision job cancelled",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Timeline / get-by-id (registered last -- see module docstring)
# ============================================================================


@router.get(
    "/{job_id}/timeline",
    response_model=ApiResponse[ProvisionTimelineResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.read"))],
)
async def get_provision_timeline(
    request: Request,
    job_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    entries = await service.get_timeline(
        job_id, requesting_organization_id=requesting_organization_id
    )
    payload = ProvisionTimelineResponse(
        job_id=str(job_id), entries=[_timeline_entry_response(e) for e in entries]
    )
    return build_response(
        success=True,
        message="Provision timeline retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{job_id}",
    response_model=ApiResponse[ProvisionJobResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("provisioning_engine.read"))],
)
async def get_provision_job(
    request: Request,
    job_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ProvisioningEngineService = Depends(get_provisioning_engine_service),
):
    job = await service.get_job(
        job_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Provision job retrieved",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

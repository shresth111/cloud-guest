"""FastAPI routes for the Queue Management Engine domain: reusable
:class:`~.models.QueueProfile` CRUD, :class:`~.models.QueueAssignment`
create/move/expire, the two real device operations (apply/remove -- see
``service.py``'s own module docstring on why "Enable"/"Disable" are not
separate methods), a reset (remove + re-apply, clearing device-side
counters), history (a read-model, not a separate table), and
:class:`~.models.QueueTemplate`/:class:`~.models.QueueSchedule` CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
extended ``bandwidth.*`` permission keys (this domain reuses the
pre-existing ``PermissionModule.BANDWIDTH`` key -- see ``dependencies.py``'s
own module docstring) and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``QueueManagementService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /queue/assignments`` is registered
*before* ``GET /queue/assignments/{assignment_id}`` so Starlette's
first-match-wins routing resolves the literal path first -- mirrors the
same discipline every other domain's router already follows for a list
route living alongside a by-id route.
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

from .constants import QueueScheduleType, QueueStatus, QueueTargetType
from .dependencies import get_queue_management_service
from .models import QueueAssignment, QueueProfile, QueueSchedule, QueueTemplate
from .schemas import (
    MessageResponse,
    QueueActionRequest,
    QueueAssignmentCreateRequest,
    QueueAssignmentListResponse,
    QueueAssignmentMoveRequest,
    QueueAssignmentResponse,
    QueueProfileCreateRequest,
    QueueProfileListResponse,
    QueueProfileResponse,
    QueueProfileUpdateRequest,
    QueueScheduleCreateRequest,
    QueueScheduleListResponse,
    QueueScheduleResponse,
    QueueTemplateCreateRequest,
    QueueTemplateListResponse,
    QueueTemplateResponse,
)
from .service import QueueManagementService

router = APIRouter(prefix="/queue", tags=["Queue Management"])


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


def _profile_response(profile: QueueProfile) -> QueueProfileResponse:
    return QueueProfileResponse(
        id=str(profile.id),
        organization_id=str(profile.organization_id)
        if profile.organization_id
        else None,
        name=profile.name,
        description=profile.description,
        download_rate_kbps=profile.download_rate_kbps,
        upload_rate_kbps=profile.upload_rate_kbps,
        burst_download_kbps=profile.burst_download_kbps,
        burst_upload_kbps=profile.burst_upload_kbps,
        burst_threshold_kbps=profile.burst_threshold_kbps,
        burst_time_seconds=profile.burst_time_seconds,
        priority=profile.priority,
        queue_type=profile.queue_type,
        is_system_profile=profile.is_system_profile,
        is_active=profile.is_active,
        created_at=profile.created_at,
    )


def _schedule_response(schedule: QueueSchedule) -> QueueScheduleResponse:
    return QueueScheduleResponse(
        id=str(schedule.id),
        organization_id=str(schedule.organization_id)
        if schedule.organization_id
        else None,
        name=schedule.name,
        schedule_type=schedule.schedule_type,
        days_of_week=schedule.days_of_week,
        start_time=schedule.start_time,
        end_time=schedule.end_time,
        specific_dates=schedule.specific_dates,
        timezone=schedule.timezone,
        is_active=schedule.is_active,
        created_at=schedule.created_at,
    )


def _template_response(template: QueueTemplate) -> QueueTemplateResponse:
    return QueueTemplateResponse(
        id=str(template.id),
        organization_id=str(template.organization_id)
        if template.organization_id
        else None,
        name=template.name,
        persona=template.persona,
        description=template.description,
        queue_profile_id=str(template.queue_profile_id)
        if template.queue_profile_id
        else None,
        default_queue_schedule_id=str(template.default_queue_schedule_id)
        if template.default_queue_schedule_id
        else None,
        is_active=template.is_active,
        created_at=template.created_at,
    )


def _assignment_response(assignment: QueueAssignment) -> QueueAssignmentResponse:
    return QueueAssignmentResponse(
        id=str(assignment.id),
        organization_id=str(assignment.organization_id),
        location_id=str(assignment.location_id) if assignment.location_id else None,
        router_id=str(assignment.router_id) if assignment.router_id else None,
        target_type=assignment.target_type,
        target_id=str(assignment.target_id) if assignment.target_id else None,
        device_target=assignment.device_target,
        device_queue_id=assignment.device_queue_id,
        queue_profile_id=str(assignment.queue_profile_id)
        if assignment.queue_profile_id
        else None,
        queue_schedule_id=str(assignment.queue_schedule_id)
        if assignment.queue_schedule_id
        else None,
        status=assignment.status,
        priority_override=assignment.priority_override,
        applied_at=assignment.applied_at,
        expires_at=assignment.expires_at,
        error_message=assignment.error_message,
        superseded_by_assignment_id=str(assignment.superseded_by_assignment_id)
        if assignment.superseded_by_assignment_id
        else None,
        created_at=assignment.created_at,
    )


# ============================================================================
# Queue profiles
# ============================================================================


@router.post(
    "/profiles",
    response_model=ApiResponse[QueueProfileResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("bandwidth.create"))],
)
async def create_queue_profile(
    request: Request,
    payload: QueueProfileCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    profile = await service.create_profile(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        description=payload.description,
        download_rate_kbps=payload.download_rate_kbps,
        upload_rate_kbps=payload.upload_rate_kbps,
        burst_download_kbps=payload.burst_download_kbps,
        burst_upload_kbps=payload.burst_upload_kbps,
        burst_threshold_kbps=payload.burst_threshold_kbps,
        burst_time_seconds=payload.burst_time_seconds,
        priority=payload.priority,
        is_system_profile=payload.is_system_profile,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Queue profile created",
        data=_profile_response(profile).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/profiles",
    response_model=ApiResponse[QueueProfileListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def list_queue_profiles(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    profiles, meta = await service.list_profiles(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = QueueProfileListResponse(
        items=[_profile_response(p) for p in profiles], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Queue profiles retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/profiles/{profile_id}",
    response_model=ApiResponse[QueueProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def get_queue_profile(
    request: Request,
    profile_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    profile = await service.get_profile(
        profile_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Queue profile retrieved",
        data=_profile_response(profile).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/profiles/{profile_id}",
    response_model=ApiResponse[QueueProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.update"))],
)
async def update_queue_profile(
    request: Request,
    profile_id: uuid.UUID,
    payload: QueueProfileUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    profile = await service.update_profile(
        profile_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Queue profile updated",
        data=_profile_response(profile).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/profiles/{profile_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.delete"))],
)
async def delete_queue_profile(
    request: Request,
    profile_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    await service.delete_profile(
        profile_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Queue profile deleted",
        data=MessageResponse(message="Queue profile deleted").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Queue assignments: create / list / move / expire
# ============================================================================


@router.post(
    "/assign",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("bandwidth.create"))],
)
async def create_queue_assignment(
    request: Request,
    payload: QueueAssignmentCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.create_assignment(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        target_type=QueueTargetType(payload.target_type),
        target_id=uuid.UUID(payload.target_id) if payload.target_id else None,
        router_id=uuid.UUID(payload.router_id) if payload.router_id else None,
        location_id=uuid.UUID(payload.location_id) if payload.location_id else None,
        device_target=payload.device_target,
        queue_profile_id=uuid.UUID(payload.queue_profile_id)
        if payload.queue_profile_id
        else None,
        queue_schedule_id=uuid.UUID(payload.queue_schedule_id)
        if payload.queue_schedule_id
        else None,
        priority_override=payload.priority_override,
        expires_at=payload.expires_at,
    )
    return build_response(
        success=True,
        message="Queue assignment created",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/assign/{assignment_id}",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.execute"))],
)
async def move_queue_assignment(
    request: Request,
    assignment_id: uuid.UUID,
    payload: QueueAssignmentMoveRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.move_queue(
        assignment_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        new_queue_profile_id=uuid.UUID(payload.new_queue_profile_id)
        if payload.new_queue_profile_id
        else None,
        new_queue_schedule_id=uuid.UUID(payload.new_queue_schedule_id)
        if payload.new_queue_schedule_id
        else None,
        auto_apply=payload.auto_apply,
    )
    return build_response(
        success=True,
        message="Queue assignment moved",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/assign/{assignment_id}",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.execute"))],
)
async def expire_queue_assignment(
    request: Request,
    assignment_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.expire_assignment(
        assignment_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Queue assignment expired",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/assignments",
    response_model=ApiResponse[QueueAssignmentListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def list_queue_assignments(
    request: Request,
    target_type: QueueTargetType | None = Query(default=None),
    target_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    assignment_status: QueueStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignments, meta = await service.list_assignments(
        requesting_organization_id=requesting_organization_id,
        target_type=target_type,
        target_id=target_id,
        router_id=router_id,
        status=assignment_status,
        page=page,
        page_size=page_size,
    )
    payload = QueueAssignmentListResponse(
        items=[_assignment_response(a) for a in assignments], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Queue assignments retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/assignments/{assignment_id}",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def get_queue_assignment(
    request: Request,
    assignment_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.get_assignment(
        assignment_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Queue assignment retrieved",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Queue lifecycle: apply / remove / reset
# ============================================================================


@router.post(
    "/apply",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.execute"))],
)
async def apply_queue(
    request: Request,
    payload: QueueActionRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.apply_queue(
        uuid.UUID(payload.assignment_id),
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Queue applied",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/remove",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.execute"))],
)
async def remove_queue(
    request: Request,
    payload: QueueActionRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.remove_queue(
        uuid.UUID(payload.assignment_id),
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Queue removed",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/reset",
    response_model=ApiResponse[QueueAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.execute"))],
)
async def reset_queue(
    request: Request,
    payload: QueueActionRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignment = await service.reset_queue(
        uuid.UUID(payload.assignment_id),
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Queue reset",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# History (read-model)
# ============================================================================


@router.get(
    "/history",
    response_model=ApiResponse[QueueAssignmentListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def get_queue_history(
    request: Request,
    target_type: QueueTargetType = Query(...),
    target_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    assignments, meta = await service.get_history(
        target_type=target_type,
        target_id=target_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = QueueAssignmentListResponse(
        items=[_assignment_response(a) for a in assignments], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Queue history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Queue templates
# ============================================================================


@router.post(
    "/templates",
    response_model=ApiResponse[QueueTemplateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("bandwidth.create"))],
)
async def create_queue_template(
    request: Request,
    payload: QueueTemplateCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    template = await service.create_template(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        persona=payload.persona,
        description=payload.description,
        queue_profile_id=uuid.UUID(payload.queue_profile_id)
        if payload.queue_profile_id
        else None,
        default_queue_schedule_id=uuid.UUID(payload.default_queue_schedule_id)
        if payload.default_queue_schedule_id
        else None,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Queue template created",
        data=_template_response(template).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/templates",
    response_model=ApiResponse[QueueTemplateListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def list_queue_templates(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    templates, meta = await service.list_templates(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = QueueTemplateListResponse(
        items=[_template_response(t) for t in templates], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Queue templates retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Queue schedules
# ============================================================================


@router.post(
    "/schedules",
    response_model=ApiResponse[QueueScheduleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("bandwidth.create"))],
)
async def create_queue_schedule(
    request: Request,
    payload: QueueScheduleCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    schedule = await service.create_schedule(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        schedule_type=QueueScheduleType(payload.schedule_type),
        days_of_week=payload.days_of_week,
        start_time=payload.start_time,
        end_time=payload.end_time,
        specific_dates=payload.specific_dates,
        timezone=payload.timezone,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Queue schedule created",
        data=_schedule_response(schedule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/schedules",
    response_model=ApiResponse[QueueScheduleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("bandwidth.read"))],
)
async def list_queue_schedules(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: QueueManagementService = Depends(get_queue_management_service),
):
    schedules, meta = await service.list_schedules(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = QueueScheduleListResponse(
        items=[_schedule_response(s) for s in schedules], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Queue schedules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

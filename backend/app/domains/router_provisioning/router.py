"""FastAPI routes for the Router Provisioning domain: configuration
templates/variables/profiles/versions, device-initiated enrollment +
approval, the provisioning queue (backup/restore/factory-reset/apply/
rollback), router secret rotation, and health/event history.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching every other domain's router -- except the
device-facing enrollment-submission endpoint (``POST /router-enrollment``),
which follows BE-008's own ``ProvisioningCheckInRequest``/
``ProvisioningCheckInResponse`` precedent of a deliberately minimal, non-
envelope response shape for the one endpoint in this API surface not aimed
at a rich, user-facing client.

Every user-facing (authenticated) endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded
``router_provisioning.*``/``templates.*`` permission keys -- this domain
defines no permission keys of its own -- and resolves ``CurrentOrganization``
(``X-Organization-Id``), passed through to ``RouterProvisioningService`` as
``requesting_organization_id`` so tenant scoping is enforced the same way
every other domain's router enforces it (in practice, almost entirely
inherited for free: every router-scoped method here resolves the router via
``RouterService.get_router``, which already raises
``CrossOrganizationRouterAccessError`` on a cross-tenant access attempt).

**The enrollment-submission endpoint is not a normal authenticated-user
endpoint.** ``POST /router-enrollment`` carries no
``RequirePermission``/``CurrentUser`` dependency at all -- mirroring BE-008's
``POST /routers/provisioning/check-in``, the physical device submitting an
enrollment request has no platform user identity or JWT yet (it hasn't even
been approved into a ``Router`` record). Unlike check-in (which at least
has a bearer provisioning token to validate), a first-contact enrollment
request has no credential whatsoever to authenticate with -- the "minimal
identity check" this endpoint performs is entirely the serial-number/MAC-
address collision check (``RouterAlreadyRegisteredError``/
``DuplicatePendingEnrollmentError``) done server-side after submission, not
anything about the caller itself. This is an accepted, documented trust
boundary: anyone can *submit* an enrollment request, but nothing happens to
the platform's real state until an authenticated, permissioned admin
*approves* it (which is exactly why approval, not submission, is the
``router_provisioning.approve``-gated step).

**Queue-completion (``complete_provisioning_job``) is intentionally not
exposed over HTTP at all** -- see ``service.py``'s module docstring: it is
the seam a future ``app.domains.router_agent`` module calls back through
after actually performing a device-side action, and this module's job is
the workflow/queue side only, not a live-dispatch mechanism.
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

from .constants import ConfigVariableScope
from .dependencies import get_router_provisioning_service
from .models import (
    ConfigProfile,
    ConfigTemplate,
    ConfigVariable,
    ConfigVersion,
    ProvisioningJob,
    RouterEnrollmentRequest,
    RouterEvent,
    RouterHealthSnapshot,
)
from .schemas import (
    ConfigProfileAssignRequest,
    ConfigProfileAssignResponse,
    ConfigProfileResponse,
    ConfigTemplateCreateRequest,
    ConfigTemplateListResponse,
    ConfigTemplateResponse,
    ConfigTemplateUpdateRequest,
    ConfigVariableCreateRequest,
    ConfigVariableListResponse,
    ConfigVariableResponse,
    ConfigVariableUpdateRequest,
    ConfigVersionApplyResponse,
    ConfigVersionDiffResponse,
    ConfigVersionListResponse,
    ConfigVersionResponse,
    ConfigVersionSummary,
    MessageResponse,
    ProvisioningJobResponse,
    ProvisioningStatusResponse,
    RouterEnrollmentApproveRequest,
    RouterEnrollmentApproveResponse,
    RouterEnrollmentListResponse,
    RouterEnrollmentRejectRequest,
    RouterEnrollmentResponse,
    RouterEnrollmentSubmitRequest,
    RouterEventListResponse,
    RouterEventResponse,
    RouterHealthHistoryResponse,
    RouterHealthSnapshotRequest,
    RouterHealthSnapshotResponse,
    RouterSecretRotationResponse,
    VendorCapabilitiesListResponse,
    VendorCapabilitiesResponse,
)
from .service import RouterProvisioningService

router = APIRouter(tags=["Router Provisioning"])


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


def _template_response(template: ConfigTemplate) -> ConfigTemplateResponse:
    return ConfigTemplateResponse(
        id=str(template.id),
        organization_id=str(template.organization_id)
        if template.organization_id
        else None,
        is_system_template=template.is_system_template,
        name=template.name,
        description=template.description,
        applicable_router_model=template.applicable_router_model,
        vendor=template.vendor,
        template_content=template.template_content,
        is_active=template.is_active,
        created_at=template.created_at,
        updated_at=template.updated_at,
    )


def _variable_response(variable: ConfigVariable) -> ConfigVariableResponse:
    return ConfigVariableResponse(
        id=str(variable.id),
        scope_type=variable.scope_type,
        organization_id=str(variable.organization_id)
        if variable.organization_id
        else None,
        location_id=str(variable.location_id) if variable.location_id else None,
        router_id=str(variable.router_id) if variable.router_id else None,
        key=variable.key,
        value=None if variable.is_secret else variable.value,
        is_secret=variable.is_secret,
        created_at=variable.created_at,
        updated_at=variable.updated_at,
    )


def _profile_response(profile: ConfigProfile) -> ConfigProfileResponse:
    return ConfigProfileResponse(
        id=str(profile.id),
        router_id=str(profile.router_id),
        template_id=str(profile.template_id),
        assigned_by_user_id=str(profile.assigned_by_user_id)
        if profile.assigned_by_user_id
        else None,
        assigned_at=profile.assigned_at,
    )


def _version_summary(version: ConfigVersion) -> ConfigVersionSummary:
    return ConfigVersionSummary(
        id=str(version.id),
        router_id=str(version.router_id),
        profile_id=str(version.profile_id) if version.profile_id else None,
        version_number=version.version_number,
        status=version.status,
        is_backup=version.is_backup,
        rollback_of_version_id=str(version.rollback_of_version_id)
        if version.rollback_of_version_id
        else None,
        created_by_user_id=str(version.created_by_user_id)
        if version.created_by_user_id
        else None,
        applied_at=version.applied_at,
        created_at=version.created_at,
    )


def _version_response(version: ConfigVersion) -> ConfigVersionResponse:
    return ConfigVersionResponse(
        **_version_summary(version).model_dump(),
        rendered_content=version.rendered_content,
    )


def _enrollment_response(
    enrollment: RouterEnrollmentRequest,
) -> RouterEnrollmentResponse:
    return RouterEnrollmentResponse(
        id=str(enrollment.id),
        serial_number=enrollment.serial_number,
        mac_address=enrollment.mac_address,
        model=enrollment.model,
        status=enrollment.status,
        requested_at=enrollment.requested_at,
        reviewed_by_user_id=str(enrollment.reviewed_by_user_id)
        if enrollment.reviewed_by_user_id
        else None,
        reviewed_at=enrollment.reviewed_at,
        rejection_reason=enrollment.rejection_reason,
        approved_router_id=str(enrollment.approved_router_id)
        if enrollment.approved_router_id
        else None,
    )


def _job_response(job: ProvisioningJob) -> ProvisioningJobResponse:
    return ProvisioningJobResponse(
        id=str(job.id),
        router_id=str(job.router_id),
        job_type=job.job_type,
        status=job.status,
        payload=job.payload,
        attempts=job.attempts,
        max_attempts=job.max_attempts,
        scheduled_at=job.scheduled_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        requested_by_user_id=str(job.requested_by_user_id)
        if job.requested_by_user_id
        else None,
        created_at=job.created_at,
    )


def _health_snapshot_response(
    snapshot: RouterHealthSnapshot,
) -> RouterHealthSnapshotResponse:
    return RouterHealthSnapshotResponse(
        id=str(snapshot.id),
        router_id=str(snapshot.router_id),
        recorded_at=snapshot.recorded_at,
        health_status=snapshot.health_status,
        cpu_usage_percent=snapshot.cpu_usage_percent,
        memory_usage_percent=snapshot.memory_usage_percent,
        uptime_seconds=snapshot.uptime_seconds,
        connected_clients_count=snapshot.connected_clients_count,
    )


def _event_response(event: RouterEvent) -> RouterEventResponse:
    return RouterEventResponse(
        id=str(event.id),
        router_id=str(event.router_id),
        event_type=event.event_type,
        message=event.message,
        occurred_at=event.occurred_at,
        event_metadata=event.event_metadata,
    )


# ============================================================================
# Vendor adapters (Provisioning Engine extension -- see adapters.py)
# ============================================================================


@router.get(
    "/router-provisioning/vendors",
    response_model=ApiResponse[VendorCapabilitiesListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def list_vendor_capabilities(
    request: Request,
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    """Every registered ``ProvisioningAdapterProtocol`` implementation's
    real, static capability description -- see ``adapters.py``'s own module
    docstring for what this is (and is not: no live device connection, no
    command execution)."""
    capabilities = service.list_vendor_capabilities()
    payload = VendorCapabilitiesListResponse(
        items=[VendorCapabilitiesResponse(**c) for c in capabilities]
    )
    return build_response(
        success=True,
        message="Vendor capabilities retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Config templates
# ============================================================================


@router.get(
    "/router-templates",
    response_model=ApiResponse[ConfigTemplateListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.read"))],
)
async def list_templates(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    templates, meta = await service.list_templates(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ConfigTemplateListResponse(
        items=[_template_response(t) for t in templates], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Config templates retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/router-templates",
    response_model=ApiResponse[ConfigTemplateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("templates.create"))],
)
async def create_template(
    request: Request,
    payload: ConfigTemplateCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    template = await service.create_template(
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        description=payload.description,
        applicable_router_model=payload.applicable_router_model,
        vendor=payload.vendor,
        template_content=payload.template_content,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Config template created",
        data=_template_response(template).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/router-templates/{template_id}",
    response_model=ApiResponse[ConfigTemplateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.read"))],
)
async def get_template(
    request: Request,
    template_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    template = await service.get_template(
        template_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Config template retrieved",
        data=_template_response(template).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/router-templates/{template_id}",
    response_model=ApiResponse[ConfigTemplateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.update"))],
)
async def update_template(
    request: Request,
    template_id: uuid.UUID,
    payload: ConfigTemplateUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    updated = await service.update_template(
        actor_user_id=uuid.UUID(user.id),
        template_id=template_id,
        requesting_organization_id=requesting_organization_id,
        data=payload.model_dump(exclude_unset=True),
    )
    return build_response(
        success=True,
        message="Config template updated",
        data=_template_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/router-templates/{template_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.delete"))],
)
async def delete_template(
    request: Request,
    template_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    await service.delete_template(
        actor_user_id=uuid.UUID(user.id),
        template_id=template_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Config template deactivated",
        data=MessageResponse(message="Config template deactivated").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Config variables
# ============================================================================


@router.get(
    "/router-templates/variables",
    response_model=ApiResponse[ConfigVariableListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.read"))],
)
async def list_variables(
    request: Request,
    scope_type: ConfigVariableScope | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    variables, meta = await service.list_variables(
        scope_type=scope_type, page=page, page_size=page_size
    )
    payload = ConfigVariableListResponse(
        items=[_variable_response(v) for v in variables], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Config variables retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/router-templates/variables",
    response_model=ApiResponse[ConfigVariableResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("templates.create"))],
)
async def create_variable(
    request: Request,
    payload: ConfigVariableCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    scope_id = uuid.UUID(payload.scope_id) if payload.scope_id else None
    variable = await service.create_variable(
        actor_user_id=uuid.UUID(user.id),
        scope_type=payload.scope_type,
        key=payload.key,
        value=payload.value,
        is_secret=payload.is_secret,
        organization_id=scope_id
        if payload.scope_type == ConfigVariableScope.ORGANIZATION
        else None,
        location_id=scope_id
        if payload.scope_type == ConfigVariableScope.LOCATION
        else None,
        router_id=scope_id
        if payload.scope_type == ConfigVariableScope.ROUTER
        else None,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Config variable created",
        data=_variable_response(variable).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/router-templates/variables/{variable_id}",
    response_model=ApiResponse[ConfigVariableResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.update"))],
)
async def update_variable(
    request: Request,
    variable_id: uuid.UUID,
    payload: ConfigVariableUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    updated = await service.update_variable(
        actor_user_id=uuid.UUID(user.id),
        variable_id=variable_id,
        value=payload.value,
        is_secret=payload.is_secret,
    )
    return build_response(
        success=True,
        message="Config variable updated",
        data=_variable_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/router-templates/variables/{variable_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("templates.delete"))],
)
async def delete_variable(
    request: Request,
    variable_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    await service.delete_variable(
        actor_user_id=uuid.UUID(user.id), variable_id=variable_id
    )
    return build_response(
        success=True,
        message="Config variable deleted",
        data=MessageResponse(message="Config variable deleted").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Config profile assignment
# ============================================================================


@router.post(
    "/routers/{router_id}/config-profile",
    response_model=ApiResponse[ConfigProfileAssignResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("router_provisioning.manage"))],
)
async def assign_config_profile(
    request: Request,
    router_id: uuid.UUID,
    payload: ConfigProfileAssignRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    profile, version = await service.assign_profile(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        template_id=uuid.UUID(payload.template_id),
        requesting_organization_id=requesting_organization_id,
    )
    result = ConfigProfileAssignResponse(
        profile=_profile_response(profile), version=_version_response(version)
    )
    return build_response(
        success=True,
        message="Config profile assigned; draft version created",
        data=result.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Config versions
# ============================================================================


@router.get(
    "/routers/{router_id}/config-versions",
    response_model=ApiResponse[ConfigVersionListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def list_config_versions(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    versions, meta = await service.list_versions(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ConfigVersionListResponse(
        items=[_version_summary(v) for v in versions], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Config versions retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/config-versions/{version_id}",
    response_model=ApiResponse[ConfigVersionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def get_config_version(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    version = await service.get_version(
        router_id=router_id,
        version_id=version_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Config version retrieved",
        data=_version_response(version).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/config-versions/{version_id}/diff/{other_version_id}",
    response_model=ApiResponse[ConfigVersionDiffResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def diff_config_versions(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    other_version_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    version_a, version_b, diff_lines = await service.diff_versions(
        router_id=router_id,
        version_id=version_id,
        other_version_id=other_version_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = ConfigVersionDiffResponse(
        router_id=str(router_id),
        from_version_id=str(version_a.id),
        from_version_number=version_a.version_number,
        to_version_id=str(version_b.id),
        to_version_number=version_b.version_number,
        diff_lines=diff_lines,
    )
    return build_response(
        success=True,
        message="Config version diff computed",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/config-versions/{version_id}/rollback",
    response_model=ApiResponse[ConfigVersionResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("router_provisioning.manage"))],
)
async def rollback_config_version(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    new_version = await service.rollback_to_version(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        target_version_id=version_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message=(
            "Rollback draft version created -- apply it to actually push "
            "this configuration"
        ),
        data=_version_response(new_version).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/config-versions/{version_id}/apply",
    response_model=ApiResponse[ConfigVersionApplyResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("router_provisioning.execute"))],
)
async def apply_config_version(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    version, job = await service.apply_version(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        version_id=version_id,
        requesting_organization_id=requesting_organization_id,
    )
    result = ConfigVersionApplyResponse(
        version=_version_response(version), job=_job_response(job)
    )
    return build_response(
        success=True,
        message="Config version queued for application",
        data=result.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Device-initiated enrollment
# ============================================================================


@router.post(
    "/router-enrollment",
    response_model=ApiResponse[RouterEnrollmentResponse],
    status_code=status.HTTP_201_CREATED,
)
async def submit_enrollment(
    request: Request,
    payload: RouterEnrollmentSubmitRequest,
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    """Presented by the physical device itself -- see module docstring."""
    enrollment = await service.submit_enrollment(
        serial_number=payload.serial_number,
        mac_address=payload.mac_address,
        model=payload.model,
    )
    return build_response(
        success=True,
        message="Enrollment request submitted, pending admin approval",
        data=_enrollment_response(enrollment).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/router-enrollment",
    response_model=ApiResponse[RouterEnrollmentListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def list_pending_enrollments(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    enrollments, meta = await service.list_pending_enrollments(
        page=page, page_size=page_size
    )
    payload = RouterEnrollmentListResponse(
        items=[_enrollment_response(e) for e in enrollments], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Pending enrollment requests retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/router-enrollment/{enrollment_id}/approve",
    response_model=ApiResponse[RouterEnrollmentApproveResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("router_provisioning.approve"))],
)
async def approve_enrollment(
    request: Request,
    enrollment_id: uuid.UUID,
    payload: RouterEnrollmentApproveRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    enrollment, router_device = await service.approve_enrollment(
        actor_user_id=uuid.UUID(user.id),
        enrollment_id=enrollment_id,
        requesting_organization_id=requesting_organization_id,
        location_id=uuid.UUID(payload.location_id),
        name=payload.name,
        management_ip_address=payload.management_ip_address,
        public_ip_address=payload.public_ip_address,
        api_username=payload.api_username,
        api_secret=payload.api_secret,
    )
    result = RouterEnrollmentApproveResponse(
        enrollment=_enrollment_response(enrollment), router_id=str(router_device.id)
    )
    return build_response(
        success=True,
        message="Enrollment approved; router registered as pending_provisioning",
        data=result.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/router-enrollment/{enrollment_id}/reject",
    response_model=ApiResponse[RouterEnrollmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.approve"))],
)
async def reject_enrollment(
    request: Request,
    enrollment_id: uuid.UUID,
    payload: RouterEnrollmentRejectRequest,
    user: AuthUser = Depends(CurrentUser),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    enrollment = await service.reject_enrollment(
        actor_user_id=uuid.UUID(user.id),
        enrollment_id=enrollment_id,
        rejection_reason=payload.rejection_reason,
    )
    return build_response(
        success=True,
        message="Enrollment rejected",
        data=_enrollment_response(enrollment).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Provisioning status / backup / restore / factory reset / secret rotation
# ============================================================================


@router.get(
    "/routers/{router_id}/provisioning-status",
    response_model=ApiResponse[ProvisioningStatusResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def get_provisioning_status(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    result = await service.get_provisioning_status(
        router_id=router_id, requesting_organization_id=requesting_organization_id
    )
    payload = ProvisioningStatusResponse(
        router_id=str(result.router.id),
        router_status=result.router.status,
        profile=_profile_response(result.profile) if result.profile else None,
        latest_version=_version_summary(result.latest_version)
        if result.latest_version
        else None,
        active_jobs=[_job_response(job) for job in result.active_jobs],
    )
    return build_response(
        success=True,
        message="Provisioning status retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/backup",
    response_model=ApiResponse[ProvisioningJobResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("router_provisioning.execute"))],
)
async def create_backup(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    job = await service.create_backup(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Backup job queued",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/restore/{backup_id}",
    response_model=ApiResponse[ProvisioningJobResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("router_provisioning.execute"))],
)
async def restore_backup(
    request: Request,
    router_id: uuid.UUID,
    backup_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    job = await service.restore_backup(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        backup_version_id=backup_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Restore job queued",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/factory-reset",
    response_model=ApiResponse[ProvisioningJobResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("router_provisioning.execute"))],
)
async def factory_reset(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    job = await service.factory_reset(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Factory reset job queued",
        data=_job_response(job).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/rotate-secret",
    response_model=ApiResponse[RouterSecretRotationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.manage"))],
)
async def rotate_secret(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    updated_router, new_secret = await service.rotate_secret(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = RouterSecretRotationResponse(
        router_id=str(updated_router.id),
        api_username=updated_router.api_username,
        new_secret=new_secret,
        rotated_at=updated_router.updated_at,
    )
    return build_response(
        success=True,
        message=(
            "Router API credentials rotated -- store the new secret now, it "
            "will not be shown again"
        ),
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Health / event history
# ============================================================================


@router.post(
    "/routers/{router_id}/health-snapshot",
    response_model=ApiResponse[RouterHealthSnapshotResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("router_provisioning.manage"))],
)
async def record_health_snapshot(
    request: Request,
    router_id: uuid.UUID,
    payload: RouterHealthSnapshotRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    """Supplements BE-008's own ``POST /routers/{id}/heartbeat`` -- see
    module docstring. Additive beyond the module brief's literal endpoint
    list, invited by the brief's own composition guidance ("a new endpoint
    that supplements it") -- see ``docs/router_provisioning/FLOW.md``."""
    _router_device, snapshot = await service.record_health_snapshot(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        cpu_usage_percent=payload.cpu_usage_percent,
        memory_usage_percent=payload.memory_usage_percent,
        uptime_seconds=payload.uptime_seconds,
        connected_clients_count=payload.connected_clients_count,
        routeros_version=payload.routeros_version,
        management_ip_address=payload.management_ip_address,
    )
    return build_response(
        success=True,
        message="Health snapshot recorded",
        data=_health_snapshot_response(snapshot).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/health-history",
    response_model=ApiResponse[RouterHealthHistoryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def get_health_history(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    snapshots, meta = await service.list_health_history(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = RouterHealthHistoryResponse(
        items=[_health_snapshot_response(s) for s in snapshots],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Health history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/events",
    response_model=ApiResponse[RouterEventListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("router_provisioning.read"))],
)
async def get_events(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RouterProvisioningService = Depends(get_router_provisioning_service),
):
    events, meta = await service.list_events(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = RouterEventListResponse(
        items=[_event_response(e) for e in events], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Router events retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

"""FastAPI routes for the Policy domain: policy/version/assignment lifecycle
and effective-policy resolution -- all admin-facing (RBAC-gated), unlike
most other domains in this codebase there is no guest-facing router here at
all: Policy has no anonymous caller (other domains would compose
``PolicyService`` directly, in-process, not over HTTP -- see ``service.py``'s
module docstring).

**Route ordering note:** ``GET /policies/resolve`` is registered *before*
``GET /policies/{policy_id}`` below. FastAPI/Starlette match routes in
registration order, so if the ``{policy_id}`` route were registered first,
a request for ``/policies/resolve`` would be captured by it instead (and
fail ``uuid.UUID`` path-parameter parsing) rather than ever reaching the
resolve handler -- this ordering is load-bearing, not cosmetic.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import PolicyType
from .dependencies import get_policy_service
from .models import Policy, PolicyAssignment, PolicyVersion
from .schemas import (
    PolicyAssignmentCreateRequest,
    PolicyAssignmentResponse,
    PolicyCreateRequest,
    PolicyDetailResponse,
    PolicyListResponse,
    PolicyResponse,
    PolicyVersionCreateRequest,
    PolicyVersionResponse,
    ResolvedPolicyResponse,
)
from .service import PolicyService

router = APIRouter(prefix="/policies", tags=["Policy"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _policy_response(policy: Policy) -> PolicyResponse:
    return PolicyResponse(
        id=str(policy.id),
        organization_id=str(policy.organization_id) if policy.organization_id else None,
        policy_type=PolicyType(policy.policy_type),
        name=policy.name,
        description=policy.description,
        is_active=policy.is_active,
        current_version_id=(
            str(policy.current_version_id) if policy.current_version_id else None
        ),
        created_by_user_id=(
            str(policy.created_by_user_id) if policy.created_by_user_id else None
        ),
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _version_response(version: PolicyVersion) -> PolicyVersionResponse:
    return PolicyVersionResponse(
        id=str(version.id),
        policy_id=str(version.policy_id),
        version_number=version.version_number,
        status=version.status,
        rules=version.rules,
        published_at=version.published_at,
        created_at=version.created_at,
    )


def _assignment_response(assignment: PolicyAssignment) -> PolicyAssignmentResponse:
    return PolicyAssignmentResponse(
        id=str(assignment.id),
        policy_id=str(assignment.policy_id),
        scope_type=assignment.scope_type,
        scope_id=str(assignment.scope_id) if assignment.scope_id else None,
        priority=assignment.priority,
        is_active=assignment.is_active,
        created_at=assignment.created_at,
    )


# ============================================================================
# Resolution -- registered before /{policy_id}, see module docstring.
# ============================================================================


@router.get(
    "/resolve",
    response_model=ApiResponse[ResolvedPolicyResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.read"))],
)
async def resolve_effective_policy(
    request: Request,
    policy_type: PolicyType = Query(...),
    organization_id: uuid.UUID | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    service: PolicyService = Depends(get_policy_service),
):
    resolved = await service.resolve_effective_policy(
        policy_type=policy_type,
        organization_id=organization_id,
        location_id=location_id,
    )
    return build_response(
        success=True,
        message="Effective policy resolved",
        data=ResolvedPolicyResponse(
            policy_type=resolved.policy_type,
            organization_id=resolved.organization_id,
            location_id=resolved.location_id,
            rules=resolved.rules,
            source=resolved.source,
        ).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Policy lifecycle
# ============================================================================


@router.post(
    "",
    response_model=ApiResponse[PolicyResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("policy.create"))],
)
async def create_policy(
    request: Request,
    payload: PolicyCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    policy = await service.create_policy(
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        organization_id=payload.organization_id,
        policy_type=payload.policy_type,
        name=payload.name,
        description=payload.description,
    )
    return build_response(
        success=True,
        message="Policy created",
        data=_policy_response(policy).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[PolicyListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.read"))],
)
async def list_policies(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    policy_type: PolicyType | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    policies, meta = await service.list_policies(
        requesting_organization_id=requesting_organization_id,
        policy_type=policy_type,
        page=page,
        page_size=page_size,
    )
    payload = PolicyListResponse(
        items=[_policy_response(policy) for policy in policies],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Policies retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{policy_id}",
    response_model=ApiResponse[PolicyDetailResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.read"))],
)
async def get_policy(
    request: Request,
    policy_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    policy = await service.get_policy(
        policy_id, requesting_organization_id=requesting_organization_id
    )
    versions = await service.repository.list_versions_for_policy(policy.id)
    assignments = await service.list_assignments(
        policy_id=policy.id, requesting_organization_id=requesting_organization_id
    )
    payload = PolicyDetailResponse(
        **_policy_response(policy).model_dump(),
        versions=[_version_response(v) for v in versions],
        assignments=[_assignment_response(a) for a in assignments],
    )
    return build_response(
        success=True,
        message="Policy retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{policy_id}/deactivate",
    response_model=ApiResponse[PolicyResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.execute"))],
)
async def deactivate_policy(
    request: Request,
    policy_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    policy = await service.deactivate_policy(
        policy_id=policy_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Policy deactivated",
        data=_policy_response(policy).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Versioning
# ============================================================================


@router.post(
    "/{policy_id}/versions",
    response_model=ApiResponse[PolicyVersionResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("policy.update"))],
)
async def create_policy_version(
    request: Request,
    policy_id: uuid.UUID,
    payload: PolicyVersionCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    version = await service.create_version(
        policy_id=policy_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        rules=payload.rules,
    )
    return build_response(
        success=True,
        message="Policy version created",
        data=_version_response(version).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{policy_id}/versions/{version_id}/publish",
    response_model=ApiResponse[PolicyVersionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.execute"))],
)
async def publish_policy_version(
    request: Request,
    policy_id: uuid.UUID,
    version_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    version = await service.publish_version(
        policy_id=policy_id,
        version_id=version_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Policy version published",
        data=_version_response(version).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{policy_id}/rollback",
    response_model=ApiResponse[PolicyResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.execute"))],
)
async def rollback_policy(
    request: Request,
    policy_id: uuid.UUID,
    target_version_id: uuid.UUID = Query(...),
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    policy = await service.rollback(
        policy_id=policy_id,
        target_version_id=target_version_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Policy rolled back",
        data=_policy_response(policy).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Assignments
# ============================================================================


@router.post(
    "/{policy_id}/assignments",
    response_model=ApiResponse[PolicyAssignmentResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("policy.create"))],
)
async def create_policy_assignment(
    request: Request,
    policy_id: uuid.UUID,
    payload: PolicyAssignmentCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    assignment = await service.create_assignment(
        policy_id=policy_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        priority=payload.priority,
    )
    return build_response(
        success=True,
        message="Policy assignment created",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{policy_id}/assignments",
    response_model=ApiResponse[list[PolicyAssignmentResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.read"))],
)
async def list_policy_assignments(
    request: Request,
    policy_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    assignments = await service.list_assignments(
        policy_id=policy_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Policy assignments retrieved",
        data=[_assignment_response(a).model_dump() for a in assignments],
        request_id=_request_id(request),
    )


@router.delete(
    "/{policy_id}/assignments/{assignment_id}",
    response_model=ApiResponse[PolicyAssignmentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.execute"))],
)
async def deactivate_policy_assignment(
    request: Request,
    policy_id: uuid.UUID,
    assignment_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: PolicyService = Depends(get_policy_service),
):
    assignment = await service.deactivate_assignment(
        policy_id=policy_id,
        assignment_id=assignment_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Policy assignment deactivated",
        data=_assignment_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

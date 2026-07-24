"""FastAPI routes for the RBAC domain: roles, permissions, and assignments.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching ``app/domains/auth/router.py``. Every mutating
(and cross-tenant-sensitive read) endpoint is gated by
``RequirePermission``/``RequireRole`` dependencies built on top of
``get_current_user`` -- see ``dependencies.py``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser

from .dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
    get_rbac_service,
)
from .enums import ScopeType
from .models import Permission, PermissionGroup, Role, UserRole
from .schemas import (
    MessageResponse,
    PermissionGroupResponse,
    PermissionResponse,
    RoleCloneRequest,
    RoleCreateRequest,
    RolePermissionAttachRequest,
    RoleResponse,
    RoleUpdateRequest,
    UserPermissionsResponse,
    UserRoleAssignRequest,
    UserRoleListResponse,
    UserRoleResponse,
)
from .service import RBACService

router = APIRouter(tags=["RBAC"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _role_response(role: Role, permissions: list[str]) -> RoleResponse:
    return RoleResponse(
        id=str(role.id),
        name=role.name,
        slug=role.slug,
        description=role.description,
        is_system_role=role.is_system_role,
        is_template=role.is_template,
        is_active=role.is_active,
        scope_type=ScopeType(role.scope_type),
        organization_id=str(role.organization_id) if role.organization_id else None,
        parent_role_id=str(role.parent_role_id) if role.parent_role_id else None,
        permissions=permissions,
        created_at=role.created_at,
        updated_at=role.updated_at,
    )


async def _role_permission_keys(
    rbac_service: RBACService, role_id: uuid.UUID
) -> list[str]:
    rows = await rbac_service.repository.get_role_permissions(role_id)
    return [row.permission.key for row in rows]


def _permission_response(permission: Permission) -> PermissionResponse:
    return PermissionResponse(
        id=str(permission.id),
        permission_group_id=str(permission.permission_group_id),
        key=permission.key,
        action=permission.action,  # type: ignore[arg-type]
        name=permission.name,
        description=permission.description,
        is_active=permission.is_active,
    )


def _permission_group_response(group: PermissionGroup) -> PermissionGroupResponse:
    return PermissionGroupResponse(
        id=str(group.id),
        key=group.key,
        name=group.name,
        description=group.description,
        sort_order=group.sort_order,
    )


def _user_role_response(assignment: UserRole) -> UserRoleResponse:
    return UserRoleResponse(
        id=str(assignment.id),
        user_id=str(assignment.user_id),
        role_id=str(assignment.role_id),
        scope_type=ScopeType(assignment.scope_type),
        organization_id=str(assignment.organization_id)
        if assignment.organization_id
        else None,
        location_id=str(assignment.location_id) if assignment.location_id else None,
        router_id=str(assignment.router_id) if assignment.router_id else None,
        granted_at=assignment.granted_at,
        granted_by=str(assignment.granted_by) if assignment.granted_by else None,
        expires_at=assignment.expires_at,
        is_active=assignment.is_active,
    )


# ============================================================================
# Roles
# ============================================================================


@router.get(
    "/roles",
    response_model=ApiResponse[list[RoleResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.read"))],
)
async def list_roles(
    request: Request,
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    roles = await rbac_service.list_roles(requesting_organization_id=organization_id)
    payloads = [
        _role_response(role, await _role_permission_keys(rbac_service, role.id))
        for role in roles
    ]
    return build_response(
        success=True,
        message="Roles retrieved",
        data=[payload.model_dump() for payload in payloads],
        request_id=_request_id(request),
    )


@router.post(
    "/roles",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("roles.create"))],
)
async def create_role(
    request: Request,
    payload: RoleCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    role = await rbac_service.create_role(
        actor_user_id=uuid.UUID(user.id),
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        scope_type=payload.scope_type,
        organization_id=payload.organization_id or organization_id,
        requesting_organization_id=organization_id,
        parent_role_id=payload.parent_role_id,
        is_template=payload.is_template,
        permission_keys=payload.permission_keys,
        allowed_scope_types=payload.allowed_scope_types,
    )
    return build_response(
        success=True,
        message="Role created",
        data=_role_response(
            role, await _role_permission_keys(rbac_service, role.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/roles/{role_id}",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.update"))],
)
async def update_role(
    request: Request,
    role_id: uuid.UUID,
    payload: RoleUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    data = payload.model_dump(exclude_unset=True)
    role = await rbac_service.update_role(
        actor_user_id=uuid.UUID(user.id),
        role_id=role_id,
        requesting_organization_id=organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Role updated",
        data=_role_response(
            role, await _role_permission_keys(rbac_service, role.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/roles/{role_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.delete"))],
)
async def delete_role(
    request: Request,
    role_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    await rbac_service.delete_role(
        actor_user_id=uuid.UUID(user.id),
        role_id=role_id,
        requesting_organization_id=organization_id,
    )
    return build_response(
        success=True,
        message="Role deleted",
        data=MessageResponse(message="Role deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/roles/{role_id}/clone",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("roles.manage"))],
)
async def clone_role(
    request: Request,
    role_id: uuid.UUID,
    payload: RoleCloneRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    clone = await rbac_service.clone_role(
        actor_user_id=uuid.UUID(user.id),
        source_role_id=role_id,
        requesting_organization_id=organization_id,
        new_name=payload.new_name,
        new_slug=payload.new_slug,
        target_organization_id=payload.target_organization_id or organization_id,
    )
    return build_response(
        success=True,
        message="Role cloned",
        data=_role_response(
            clone, await _role_permission_keys(rbac_service, clone.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/roles/{role_id}/activate",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.manage"))],
)
async def activate_role(
    request: Request,
    role_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    role = await rbac_service.set_role_active(
        actor_user_id=uuid.UUID(user.id),
        role_id=role_id,
        requesting_organization_id=organization_id,
        is_active=True,
    )
    return build_response(
        success=True,
        message="Role activated",
        data=_role_response(
            role, await _role_permission_keys(rbac_service, role.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/roles/{role_id}/deactivate",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.manage"))],
)
async def deactivate_role(
    request: Request,
    role_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    role = await rbac_service.set_role_active(
        actor_user_id=uuid.UUID(user.id),
        role_id=role_id,
        requesting_organization_id=organization_id,
        is_active=False,
    )
    return build_response(
        success=True,
        message="Role deactivated",
        data=_role_response(
            role, await _role_permission_keys(rbac_service, role.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/roles/{role_id}/permissions",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.manage"))],
)
async def attach_role_permission(
    request: Request,
    role_id: uuid.UUID,
    payload: RolePermissionAttachRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    await rbac_service.assign_permission_to_role(
        actor_user_id=uuid.UUID(user.id),
        role_id=role_id,
        permission_key=payload.permission_key,
        requesting_organization_id=organization_id,
    )
    role = await rbac_service.get_role(
        role_id, requesting_organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Permission attached to role",
        data=_role_response(
            role, await _role_permission_keys(rbac_service, role.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/roles/{role_id}/permissions/{permission_key}",
    response_model=ApiResponse[RoleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.manage"))],
)
async def detach_role_permission(
    request: Request,
    role_id: uuid.UUID,
    permission_key: str,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    await rbac_service.remove_permission_from_role(
        actor_user_id=uuid.UUID(user.id),
        role_id=role_id,
        permission_key=permission_key,
        requesting_organization_id=organization_id,
    )
    role = await rbac_service.get_role(
        role_id, requesting_organization_id=organization_id
    )
    return build_response(
        success=True,
        message="Permission removed from role",
        data=_role_response(
            role, await _role_permission_keys(rbac_service, role.id)
        ).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Permissions / permission groups (read-only; seeded data)
# ============================================================================


@router.get(
    "/permissions",
    response_model=ApiResponse[list[PermissionResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("permissions.read"))],
)
async def list_permissions(
    request: Request,
    permission_group_id: uuid.UUID | None = None,
    rbac_service: RBACService = Depends(get_rbac_service),
):
    permissions = await rbac_service.list_permissions(
        permission_group_id=permission_group_id
    )
    return build_response(
        success=True,
        message="Permissions retrieved",
        data=[
            _permission_response(permission).model_dump() for permission in permissions
        ],
        request_id=_request_id(request),
    )


@router.get(
    "/permission-groups",
    response_model=ApiResponse[list[PermissionGroupResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("permissions.read"))],
)
async def list_permission_groups(
    request: Request,
    rbac_service: RBACService = Depends(get_rbac_service),
):
    groups = await rbac_service.list_permission_groups()
    return build_response(
        success=True,
        message="Permission groups retrieved",
        data=[_permission_group_response(group).model_dump() for group in groups],
        request_id=_request_id(request),
    )


# ============================================================================
# User role assignment
# ============================================================================


@router.get(
    "/users/{user_id}/roles",
    response_model=ApiResponse[UserRoleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.read"))],
)
async def list_user_role_assignments(
    request: Request,
    user_id: uuid.UUID,
    rbac_service: RBACService = Depends(get_rbac_service),
):
    assignments = await rbac_service.repository.get_active_user_roles(user_id)
    payload = UserRoleListResponse(items=[_user_role_response(a) for a in assignments])
    return build_response(
        success=True,
        message="User role assignments retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/users/{user_id}/roles",
    response_model=ApiResponse[UserRoleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("roles.assign"))],
)
async def assign_role_to_user(
    request: Request,
    user_id: uuid.UUID,
    payload: UserRoleAssignRequest,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    assignment = await rbac_service.assign_role_to_user(
        actor_user_id=uuid.UUID(user.id),
        target_user_id=user_id,
        role_id=payload.role_id,
        scope_type=payload.scope_type,
        requesting_organization_id=organization_id,
        organization_id=payload.organization_id or organization_id,
        location_id=payload.location_id,
        router_id=payload.router_id,
        expires_at=payload.expires_at,
    )
    return build_response(
        success=True,
        message="Role assigned",
        data=_user_role_response(assignment).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/users/{user_id}/roles/{role_assignment_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("roles.assign"))],
)
async def revoke_role_from_user(
    request: Request,
    user_id: uuid.UUID,
    role_assignment_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    # ``role_assignment_id`` identifies the ``user_roles`` row (a user may
    # hold the same role at multiple distinct scopes -- see UserRole in
    # models.py), not the role itself; ``user_id`` in the path exists for
    # REST-conventional readability/URL clarity and consistency checking.
    await rbac_service.revoke_role_from_user(
        actor_user_id=uuid.UUID(user.id),
        assignment_id=role_assignment_id,
        requesting_organization_id=organization_id,
    )
    return build_response(
        success=True,
        message="Role revoked",
        data=MessageResponse(message="Role revoked").model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/users/{user_id}/permissions",
    response_model=ApiResponse[UserPermissionsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.read"))],
)
async def get_user_permissions(
    request: Request,
    user_id: uuid.UUID,
    rbac_service: RBACService = Depends(get_rbac_service),
):
    permissions = await rbac_service.get_user_permissions(user_id)
    return build_response(
        success=True,
        message="User permissions retrieved",
        data=UserPermissionsResponse(
            user_id=str(user_id), permissions=sorted(permissions)
        ).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Self-service
# ============================================================================


@router.get(
    "/me/permissions",
    response_model=ApiResponse[UserPermissionsResponse],
    status_code=status.HTTP_200_OK,
)
async def get_my_permissions(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    rbac_service: RBACService = Depends(get_rbac_service),
):
    permissions = await rbac_service.get_user_permissions(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Your effective permissions",
        data=UserPermissionsResponse(
            user_id=user.id, permissions=sorted(permissions)
        ).model_dump(),
        request_id=_request_id(request),
    )

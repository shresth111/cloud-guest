"""FastAPI routes for the User management/aggregation domain.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching every other domain's router. Every mutating
(and cross-tenant-sensitive read) admin endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded ``users.*``
permission keys -- this domain defines no permission keys of its own.
``GET /me``/``PUT /me`` require only an authenticated caller
(``CurrentUser``), since a user always may read/edit their own profile.

Every admin endpoint additionally resolves ``CurrentOrganization``
(``X-Organization-Id``) and passes it to ``UserService`` as
``requesting_organization_id`` so tenant scoping (an org-scoped caller may
only list/view/manage users who are active members of their own
organization, or its MSP children) is enforced the same way
``OrganizationService``/``LocationService`` enforce it -- not just left to
the permission check, which only verifies *what* the caller can do, not
*which tenant's users* they are doing it to.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser, User
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_user_service
from .schemas import (
    InviteUserRequest,
    InviteUserResponse,
    MeUpdateRequest,
    OrganizationMembershipSummary,
    RoleSummary,
    UserCreateRequest,
    UserDetailResponse,
    UserListResponse,
    UserResponse,
    UserUpdateRequest,
)
from .service import UserAggregate, UserService

router = APIRouter(tags=["Users"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=str(user.id),
        first_name=user.first_name,
        last_name=user.last_name,
        full_name=user.full_name,
        email=user.email,
        username=user.username,
        phone=user.phone,
        profile_photo=user.profile_photo,
        designation=user.designation,
        department=user.department,
        employee_id=user.employee_id,
        timezone=user.timezone,
        language=user.language,
        status=user.status,
        is_active=user.is_active,
        is_verified=user.is_verified,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def _user_detail_response(aggregate: UserAggregate) -> UserDetailResponse:
    return UserDetailResponse(
        user=_user_response(aggregate.user),
        organizations=[
            OrganizationMembershipSummary(
                organization_id=str(view.membership.organization_id),
                organization_name=view.organization_name,
                status=view.membership.status,
                is_primary_contact=view.membership.is_primary_contact,
                invited_at=view.membership.invited_at,
                joined_at=view.membership.joined_at,
            )
            for view in aggregate.memberships
        ],
        roles=[
            RoleSummary(
                id=str(role.id),
                name=role.name,
                slug=role.slug,
                scope_type=role.scope_type,
                organization_id=str(role.organization_id)
                if role.organization_id
                else None,
            )
            for role in aggregate.roles
        ],
    )


# ============================================================================
# Admin user management
# ============================================================================


@router.get(
    "/users",
    response_model=ApiResponse[UserListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.read"))],
)
async def list_users(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    is_active: bool | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    users, meta = await user_service.list_users(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        search=search,
        is_active=is_active,
    )
    payload = UserListResponse(
        items=[_user_response(user) for user in users],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Users retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/users",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("users.create"))],
)
async def create_user(
    request: Request,
    payload: UserCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    created = await user_service.create_user(
        actor_user_id=uuid.UUID(user.id),
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        username=payload.username,
        temporary_password=payload.temporary_password,
        requesting_organization_id=requesting_organization_id,
        phone=payload.phone,
        designation=payload.designation,
        department=payload.department,
        employee_id=payload.employee_id,
        timezone=payload.timezone,
        language=payload.language,
        organization_id=payload.organization_id,
        initial_role_id=payload.initial_role_id,
    )
    return build_response(
        success=True,
        message="User created",
        data=_user_response(created).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/users/invite",
    response_model=ApiResponse[InviteUserResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("users.create"))],
)
async def invite_user(
    request: Request,
    payload: InviteUserRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    """Real invitation workflow -- unlike ``POST /users``, the caller never
    supplies a password: one is generated and emailed to the invitee (see
    ``UserService.invite_user``)."""
    result = await user_service.invite_user(
        actor_user_id=uuid.UUID(user.id),
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        username=payload.username,
        requesting_organization_id=requesting_organization_id,
        phone=payload.phone,
        designation=payload.designation,
        department=payload.department,
        employee_id=payload.employee_id,
        timezone=payload.timezone,
        language=payload.language,
        organization_id=payload.organization_id,
        initial_role_id=payload.initial_role_id,
    )
    return build_response(
        success=True,
        message="User invited",
        data=InviteUserResponse(
            user=_user_response(result.user),
            temporary_password=result.temporary_password,
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/users/{user_id}",
    response_model=ApiResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.read"))],
)
async def get_user(
    request: Request,
    user_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    aggregate = await user_service.get_user_detail(
        user_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="User retrieved",
        data=_user_detail_response(aggregate).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/users/{user_id}",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.update"))],
)
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    payload: UserUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    data = payload.model_dump(exclude_unset=True)
    updated = await user_service.update_user(
        actor_user_id=uuid.UUID(user.id),
        user_id=user_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="User updated",
        data=_user_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/users/{user_id}/deactivate",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.manage"))],
)
async def deactivate_user(
    request: Request,
    user_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    updated = await user_service.deactivate_user(
        actor_user_id=uuid.UUID(user.id),
        user_id=user_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="User deactivated",
        data=_user_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/users/{user_id}/activate",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.manage"))],
)
async def activate_user(
    request: Request,
    user_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    updated = await user_service.reactivate_user(
        actor_user_id=uuid.UUID(user.id),
        user_id=user_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="User activated",
        data=_user_response(updated).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Self-service
# ============================================================================


@router.get(
    "/me",
    response_model=ApiResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
)
async def get_my_profile(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    user_service: UserService = Depends(get_user_service),
):
    aggregate = await user_service.get_me(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Your profile",
        data=_user_detail_response(aggregate).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/me",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
)
async def update_my_profile(
    request: Request,
    payload: MeUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    user_service: UserService = Depends(get_user_service),
):
    data = payload.model_dump(exclude_unset=True)
    updated = await user_service.update_self(user_id=uuid.UUID(user.id), data=data)
    return build_response(
        success=True,
        message="Your profile was updated",
        data=_user_response(updated).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

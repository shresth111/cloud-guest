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
from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.otp.dependencies import get_otp_service
from app.domains.otp.service import OtpService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_user_service
from .schemas import (
    DataMaskingOtpRequestResponse,
    DataMaskingVerifyRequest,
    ImpersonateUserRequest,
    ImpersonateUserResponse,
    ImpersonationTargetUser,
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
from .service import ImpersonationResult, UserAggregate, UserService

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
        data_masking_enabled=user.data_masking_enabled,
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
    "/users/{user_id}/force-logout",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("users.manage"))],
)
async def force_logout_user(
    request: Request,
    user_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    user_service: UserService = Depends(get_user_service),
):
    """Real, immediate session termination for another user -- revokes
    their sessions/refresh tokens and rejects any already-issued access
    token on its very next request (see
    ``UserService.force_logout_user``'s own docstring). Unlike deactivate,
    the account itself is left active -- they can sign back in right
    away, just not with the session(s) that existed a moment ago."""
    updated = await user_service.force_logout_user(
        actor_user_id=uuid.UUID(user.id),
        user_id=user_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="User logged out",
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


def _impersonation_response(result: ImpersonationResult) -> ImpersonateUserResponse:
    return ImpersonateUserResponse(
        access_token=result.access_token,
        expires_at=result.expires_at,
        target_user=ImpersonationTargetUser(
            id=str(result.target_user.id),
            full_name=result.target_user.full_name,
            email=result.target_user.email,
            username=result.target_user.username,
        ),
    )


@router.post(
    "/users/{user_id}/impersonate",
    response_model=ApiResponse[ImpersonateUserResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("users.impersonate", scope=ScopeType.GLOBAL))
    ],
)
async def impersonate_user(
    request: Request,
    user_id: uuid.UUID,
    payload: ImpersonateUserRequest,
    user: AuthUser = Depends(CurrentUser),
    user_service: UserService = Depends(get_user_service),
):
    """Mint a short-lived (~30 minute) access token identifying ``user_id``
    so a platform operator can view that customer's dashboard exactly as
    they would see it themselves. Explicitly checked at GLOBAL scope
    (``ScopeType.GLOBAL``, not scope-inferred from any ``X-Organization-Id``
    header) -- this must only ever succeed for a caller holding a genuinely
    platform-wide role, never an organization-scoped one, regardless of
    what scope headers happen to be present on the request. See
    ``UserService.impersonate_user`` for the full validation/audit
    contract."""
    result = await user_service.impersonate_user(
        actor_user_id=uuid.UUID(user.id),
        actor_email=user.email,
        user_id=user_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message=f"Impersonation session started for '{result.target_user.email}'",
        data=_impersonation_response(result).model_dump(),
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


# ============================================================================
# Self-service data-masking OTP step-up
#
# Deliberately NOT built on top of the guest-facing ``POST /otp/request``/
# ``POST /otp/verify`` endpoints (``app.domains.otp.router``) despite reusing
# their service underneath: those two endpoints are intentionally
# unauthenticated (a guest has no account to authenticate with) and take a
# client-supplied ``identifier`` -- wiring this dashboard control to them
# directly would let *any* caller, logged in or not, request/verify an OTP
# against an arbitrary email under this purpose, since neither endpoint
# checks that the caller "owns" the identifier they're operating on. Both
# endpoints below are authenticated (``CurrentUser``) and always derive the
# identifier from the caller's own account via ``_data_masking_otp_target``
# (their phone via SMS if one is on file, their email otherwise) -- never
# client-supplied -- so the OTP genuinely proves "this session belongs to
# that phone/inbox."
# ============================================================================


def _data_masking_otp_target(user: AuthUser) -> tuple[str, OtpChannel]:
    """SMS-to-phone when a phone is on file, email otherwise. Both the
    request and verify endpoints below call this with the same `user`
    (freshly loaded per-request by `CurrentUser`), so they always agree on
    which identifier the OTP was filed under -- there's no separate state
    to track which channel a given code was sent on."""
    if user.phone:
        return user.phone, OtpChannel.SMS
    return user.email, OtpChannel.EMAIL


def _mask_identifier(identifier: str, channel: OtpChannel) -> str:
    """Masked for the response message only (never logged/stored unmasked
    here beyond what OtpService itself already persists) -- e.g.
    ``+91••••••210`` or ``ad••••@example.com``."""
    if channel == OtpChannel.SMS:
        digits = "".join(c for c in identifier if c.isdigit())
        return (
            identifier
            if len(digits) <= 4
            else f"+{'•' * (len(digits) - 4)}{digits[-4:]}"
        )
    at = identifier.find("@")
    if at <= 1:
        return identifier
    return f"{identifier[:2]}{'•' * max(3, at - 2)}{identifier[at:]}"


@router.post(
    "/me/data-masking/otp",
    response_model=ApiResponse[DataMaskingOtpRequestResponse],
    status_code=status.HTTP_201_CREATED,
)
async def request_data_masking_otp(
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    otp_service: OtpService = Depends(get_otp_service),
):
    identifier, channel = _data_masking_otp_target(user)
    await otp_service.request_otp(
        identifier=identifier,
        channel=channel,
        purpose=OtpPurpose.ACCOUNT_DATA_MASKING,
        organization_id=None,
        location_id=None,
    )
    message = (
        f"Verification code sent via {channel.value} "
        f"to {_mask_identifier(identifier, channel)}"
    )
    return build_response(
        success=True,
        message=message,
        data=DataMaskingOtpRequestResponse(message=message).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/me/data-masking",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
)
async def verify_data_masking_otp(
    request: Request,
    payload: DataMaskingVerifyRequest,
    user: AuthUser = Depends(CurrentUser),
    otp_service: OtpService = Depends(get_otp_service),
    user_service: UserService = Depends(get_user_service),
):
    identifier, _channel = _data_masking_otp_target(user)
    await otp_service.verify_otp(
        identifier=identifier,
        code=payload.code,
        purpose=OtpPurpose.ACCOUNT_DATA_MASKING,
    )
    updated = await user_service.set_own_data_masking(
        user_id=uuid.UUID(user.id), masked=payload.masked
    )
    return build_response(
        success=True,
        message=(
            "Guest data is now masked"
            if payload.masked
            else "Guest data is now shown unmasked"
        ),
        data=_user_response(updated).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]

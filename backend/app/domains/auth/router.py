"""FastAPI routes for authentication: login, registration, tokens, password
and session management.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching ``app/api/v1/health/routes.py``. Domain
errors are ``CloudGuestError`` subclasses raised from the service layer and
are translated to the same envelope by the app-wide exception handlers
registered in ``app.common.exceptions``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.billing.dependencies import get_license_service
from app.domains.billing.exceptions import LicenseNotFoundError
from app.domains.billing.service import LicenseService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.enums import MembershipStatus
from app.domains.organization.models import OrganizationMember
from app.domains.organization.service import OrganizationService
from app.domains.rbac.authorization import ActiveRoleAssignment, RoleResolver

from .dependencies import (
    get_auth_service,
    get_current_user,
    get_device_info,
    get_role_resolver,
)
from .jwt import InvalidTokenError, JWTManager, TokenExpiredError
from .models import AuthUser, Session, User
from .schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MessageResponse,
    MfaDisableRequest,
    MfaEnrollResponse,
    MfaRecoveryCodesResponse,
    MfaRegenerateRecoveryCodesRequest,
    MfaVerifyRequest,
    OrganizationMembershipSummary,
    RefreshTokenRequest,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResetPasswordRequest,
    RoleAssignmentSummary,
    SessionListResponse,
    SessionResponse,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from .service import AuthService, DeviceInfo

router = APIRouter(prefix="/auth", tags=["auth"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=str(user.id),
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        username=user.username,
        phone=user.phone,
        profile_photo=user.profile_photo,
        designation=user.designation,
        department=user.department,
        timezone=user.timezone,
        language=user.language,
        status=user.status,
        is_active=user.is_active,
        is_verified=user.is_verified,
        email_verified_at=user.email_verified_at,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def _session_response(
    session: Session, *, current_session_id: uuid.UUID | None = None
) -> SessionResponse:
    return SessionResponse(
        id=str(session.id),
        device_id=session.device_id,
        device_name=session.device_name,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        location=session.location,
        is_current=current_session_id is not None and session.id == current_session_id,
        created_at=session.created_at,
        expires_at=session.expires_at,
        last_activity_at=session.last_activity_at,
        is_active=session.is_active,
    )


def _token_response(tokens) -> TokenResponse:
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        refresh_expires_in=tokens.refresh_expires_in,
    )


@router.post(
    "/login",
    response_model=ApiResponse[LoginResponse],
    status_code=status.HTTP_200_OK,
)
async def login(
    request: Request,
    payload: LoginRequest,
    device_info: DeviceInfo = Depends(get_device_info),
    auth_service: AuthService = Depends(get_auth_service),
    role_resolver: RoleResolver = Depends(get_role_resolver),
    organization_service: OrganizationService = Depends(get_organization_service),
    license_service: LicenseService = Depends(get_license_service),
):
    if payload.device_name:
        device_info.device_name = payload.device_name

    user, tokens, session_id = await auth_service.login(
        payload.email, payload.password, device_info, mfa_code=payload.mfa_code
    )

    roles = await _role_assignment_summaries(role_resolver, user.id)
    organizations = await _organization_membership_summaries(
        organization_service, license_service, user.id
    )

    return build_response(
        success=True,
        message="Login successful",
        data=LoginResponse(
            user=_user_response(user),
            tokens=_token_response(tokens),
            session_id=str(session_id),
            roles=roles,
            organizations=organizations,
        ).model_dump(),
        request_id=_request_id(request),
    )


async def _role_assignment_summaries(
    role_resolver: RoleResolver, user_id: uuid.UUID
) -> list[RoleAssignmentSummary]:
    """Every active role the caller holds, at whatever scope it was
    granted -- Enterprise SaaS Phase E's "dynamic dashboards based on
    role permissions" data source. Uses ``get_active_assignments`` (not
    ``get_active_roles``) so each summary keeps its own
    organization/location/router scope rather than a deduplicated,
    scope-less role list."""
    assignments = await role_resolver.get_active_assignments(user_id)
    return [_role_summary(item) for item in assignments]


def _role_summary(item: ActiveRoleAssignment) -> RoleAssignmentSummary:
    assignment = item.assignment
    return RoleAssignmentSummary(
        role_id=str(item.role.id),
        role_name=item.role.name,
        role_slug=item.role.slug,
        scope_type=assignment.scope_type,
        organization_id=(
            str(assignment.organization_id) if assignment.organization_id else None
        ),
        location_id=(
            str(assignment.location_id) if assignment.location_id else None
        ),
        router_id=str(assignment.router_id) if assignment.router_id else None,
    )


async def _organization_membership_summaries(
    organization_service: OrganizationService,
    license_service: LicenseService,
    user_id: uuid.UUID,
) -> list[OrganizationMembershipSummary]:
    """Every organization the caller is an *active* member of, each
    paired with that organization's currently enabled plan features
    (empty if it has no license yet -- never fabricated). Reuses Phase
    A's ``LicenseService.get_entitlement_snapshot`` directly rather than
    a second entitlement computation."""
    memberships = await organization_service.list_user_organizations(
        user_id, status=MembershipStatus.ACTIVE
    )
    return [
        await _membership_summary(organization_service, license_service, membership)
        for membership in memberships
    ]


async def _membership_summary(
    organization_service: OrganizationService,
    license_service: LicenseService,
    membership: OrganizationMember,
) -> OrganizationMembershipSummary:
    organization = await organization_service.get_organization(
        membership.organization_id
    )
    enabled_features: list[str] = []
    try:
        snapshot = await license_service.get_entitlement_snapshot(organization.id)
        enabled_features = sorted(snapshot.enabled_features)
    except LicenseNotFoundError:
        pass
    return OrganizationMembershipSummary(
        organization_id=str(organization.id),
        organization_name=organization.name,
        organization_slug=organization.slug,
        is_primary_contact=membership.is_primary_contact,
        enabled_features=enabled_features,
    )


@router.post(
    "/register",
    response_model=ApiResponse[RegisterResponse],
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: Request,
    payload: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    user, verification_token = await auth_service.register(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        username=payload.username,
        password=payload.password,
        phone=payload.phone,
        timezone=payload.timezone,
        language=payload.language,
    )

    return build_response(
        success=True,
        message=(
            "User registered successfully. Please verify your email to activate "
            "your account."
        ),
        data=RegisterResponse(
            message="User registered successfully.",
            user=_user_response(user),
            verification_email_sent=bool(verification_token),
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/refresh",
    response_model=ApiResponse[TokenResponse],
    status_code=status.HTTP_200_OK,
)
async def refresh(
    request: Request,
    payload: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    tokens = await auth_service.refresh(payload.refresh_token)

    return build_response(
        success=True,
        message="Token refreshed",
        data=_token_response(tokens).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/logout",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def logout(
    request: Request,
    payload: LogoutRequest,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    # The access token doesn't carry a session id, so logout revokes via the
    # refresh token's jti when the client supplies one.
    if payload.refresh_token:
        try:
            token_payload = JWTManager.validate_token(
                payload.refresh_token, expected_type="refresh"
            )
            await auth_service.repository.revoke_refresh_token(token_payload["jti"])
        except (InvalidTokenError, TokenExpiredError):
            pass

    return build_response(
        success=True,
        message="Logged out successfully",
        data=MessageResponse(message="Logged out successfully").model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/logout-all",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def logout_all_devices(
    request: Request,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    revoked = await auth_service.logout_all(uuid.UUID(user.id))
    message = f"Logged out of {revoked} session(s)"

    return build_response(
        success=True,
        message=message,
        data=MessageResponse(message=message).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/verify-email",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def verify_email(
    request: Request,
    payload: VerifyEmailRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.verify_email(payload.token)

    return build_response(
        success=True,
        message="Email verified successfully",
        data=MessageResponse(message="Email verified successfully").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/resend-verification",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def resend_verification(
    request: Request,
    payload: ResendVerificationRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.resend_verification(payload.email)

    message = "If an account exists with that email, a verification link has been sent."
    return build_response(
        success=True,
        message=message,
        data=MessageResponse(message=message).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/forgot-password",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.initiate_password_reset(payload.email)

    message = (
        "If an account exists with that email, a password reset link has been sent."
    )
    return build_response(
        success=True,
        message=message,
        data=MessageResponse(message=message).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/reset-password",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.reset_password(payload.token, payload.new_password)

    message = "Password reset successfully. Please login with your new password."
    return build_response(
        success=True,
        message=message,
        data=MessageResponse(message=message).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/change-password",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.change_password(
        uuid.UUID(user.id), payload.current_password, payload.new_password
    )

    message = "Password changed successfully. Please login again."
    return build_response(
        success=True,
        message=message,
        data=MessageResponse(message=message).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/me",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_200_OK,
)
async def me(
    request: Request,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    full_user = await auth_service.repository.get_user_by_id(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Current user",
        data=_user_response(full_user).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/sessions",
    response_model=ApiResponse[SessionListResponse],
    status_code=status.HTTP_200_OK,
)
async def list_sessions(
    request: Request,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    sessions = await auth_service.list_sessions(uuid.UUID(user.id))

    return build_response(
        success=True,
        message="Active sessions",
        data=SessionListResponse(
            sessions=[_session_response(s) for s in sessions],
            total=len(sessions),
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/sessions/{session_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def revoke_session(
    request: Request,
    session_id: str,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.revoke_session(uuid.UUID(session_id))

    return build_response(
        success=True,
        message="Session revoked",
        data=MessageResponse(message="Session revoked").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# MFA/TOTP -- self-service only (no RBAC gate: a user manages their own
# second factor, never another user's), mirroring /me's identical posture.
# ============================================================================


@router.post(
    "/mfa/enroll",
    response_model=ApiResponse[MfaEnrollResponse],
    status_code=status.HTTP_200_OK,
)
async def enroll_mfa(
    request: Request,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    secret, provisioning_uri = await auth_service.enroll_mfa(uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Scan the provisioning URI with an authenticator app, then verify",
        data=MfaEnrollResponse(
            secret=secret, provisioning_uri=provisioning_uri
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/mfa/verify",
    response_model=ApiResponse[MfaRecoveryCodesResponse],
    status_code=status.HTTP_200_OK,
)
async def verify_mfa(
    request: Request,
    payload: MfaVerifyRequest,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    recovery_codes = await auth_service.verify_and_enable_mfa(
        uuid.UUID(user.id), payload.code
    )
    return build_response(
        success=True,
        message=(
            "MFA enabled -- store these recovery codes, they will not be "
            "shown again"
        ),
        data=MfaRecoveryCodesResponse(recovery_codes=recovery_codes).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/mfa/disable",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
)
async def disable_mfa(
    request: Request,
    payload: MfaDisableRequest,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.disable_mfa(
        uuid.UUID(user.id), password=payload.password, code=payload.code
    )
    return build_response(
        success=True,
        message="MFA disabled",
        data=MessageResponse(message="MFA disabled").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/mfa/recovery-codes/regenerate",
    response_model=ApiResponse[MfaRecoveryCodesResponse],
    status_code=status.HTTP_200_OK,
)
async def regenerate_mfa_recovery_codes(
    request: Request,
    payload: MfaRegenerateRecoveryCodesRequest,
    user: AuthUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    recovery_codes = await auth_service.regenerate_recovery_codes(
        uuid.UUID(user.id), code=payload.code
    )
    return build_response(
        success=True,
        message=(
            "Recovery codes regenerated -- store them, they will not be "
            "shown again"
        ),
        data=MfaRecoveryCodesResponse(recovery_codes=recovery_codes).model_dump(),
        request_id=_request_id(request),
    )

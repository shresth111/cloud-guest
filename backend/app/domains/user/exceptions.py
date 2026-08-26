"""User domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy does -- no route needs its own
try/except translation.

Duplicate-email/duplicate-username rejection deliberately does **not**
reinvent its own exception classes here: per the module's boundary decision
("delegate to auth's existing uniqueness constraint/error handling, don't
reinvent"), ``UserService`` raises ``app.domains.auth.service
.EmailAlreadyExistsError``/``UsernameAlreadyExistsError`` directly (re-
exported below for convenient importing from one place), reusing the exact
error shape/status code auth's own ``register()`` flow already uses for the
same condition, rather than a parallel ``user`` domain error type.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError
from app.domains.auth.service import (
    EmailAlreadyExistsError,
    UsernameAlreadyExistsError,
)

__all__ = [
    "UserError",
    "UserNotFoundError",
    "EmailAlreadyExistsError",
    "UsernameAlreadyExistsError",
    "CrossOrganizationUserAccessError",
    "InitialRoleRequiresOrganizationError",
    "SelfDeactivationNotAllowedError",
    "ImpersonationTargetInactiveError",
    "StaffImpersonationNotAllowedError",
    "SelfImpersonationNotAllowedError",
]


class UserError(CloudGuestError):
    """Base exception for user domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class UserNotFoundError(UserError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"User not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationUserAccessError(UserError):
    """A caller acting within organization A attempted to read/mutate a user
    who is not an active member of A itself or one of A's children (mirrors
    ``organization.exceptions.CrossOrganizationAccessError`` /
    ``location.exceptions.CrossOrganizationLocationAccessError``)."""

    def __init__(
        self,
        message: str = "Cannot access a user outside your own organization scope",
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class InitialRoleRequiresOrganizationError(UserError):
    """An ``initial_role_id`` was supplied at user-creation time with no
    ``organization_id`` -- the convenience initial-role-assignment feature
    only ever assigns at ``ORGANIZATION`` scope (see
    ``docs/user/USER_ARCHITECTURE.md``), which requires an organization to
    assign it against. A GLOBAL/platform-level role should instead be
    assigned afterward via RBAC's own
    ``POST /api/v1/users/{id}/roles`` endpoint."""

    def __init__(self) -> None:
        super().__init__(
            "An initial_role_id requires organization_id to also be provided",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class SelfDeactivationNotAllowedError(UserError):
    """An administrator cannot deactivate their own account through this
    endpoint -- prevents an admin from accidentally locking themselves out
    (use another administrator's session, or the dedicated session-revoking
    endpoints in ``app.domains.auth``, if that is genuinely the intent)."""

    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__(
            f"User {user_id} cannot deactivate their own account",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ImpersonationTargetInactiveError(UserError):
    """``POST /users/{id}/impersonate`` mints a real, working session as
    the target user -- an inactive (``is_active=False``) account cannot be
    impersonated, both because there is nothing legitimate to view on
    behalf of a deactivated customer and because
    ``auth.dependencies.get_current_user`` would otherwise reject the
    impersonated session's very first request anyway (see
    ``_resolve_user_from_jwt``'s own ``is_active`` check) -- reject this
    up front with a clear error instead of a confusing downstream 401."""

    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__(
            f"Cannot impersonate user {user_id}: account is not active",
            status_code=status.HTTP_409_CONFLICT,
        )


class StaffImpersonationNotAllowedError(UserError):
    """A target user holding any active GLOBAL-scope role assignment (a
    platform staff/operator account, not a customer) can never be
    impersonated -- this is the privilege-escalation-chain guard: without
    it, one operator's impersonation session could ride another
    operator's own, possibly higher, platform-wide permissions."""

    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__(
            f"Cannot impersonate user {user_id}: holds a platform-staff "
            "(global-scope) role",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class SelfImpersonationNotAllowedError(UserError):
    """A caller cannot impersonate their own account through this
    endpoint -- there is no session to distinguish; use the caller's own,
    already-authenticated session directly."""

    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__(
            f"User {user_id} cannot impersonate their own account",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UserPasswordTooWeakError(UserError):
    """Wraps ``app.domains.auth.password.PasswordStrengthError`` (a plain
    ``Exception``, not a ``CloudGuestError``) into a proper 400 with that
    validator's own message. Same gap as ``auth.service.PasswordTooWeakError``
    and ``guest.service.GuestPasswordTooWeakError`` -- confirmed reachable via
    ``POST /users`` with a `temporary_password` that satisfies the schema's
    length-only check but is missing a required character class, which
    otherwise surfaces as a raw "Internal server error" 500."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)

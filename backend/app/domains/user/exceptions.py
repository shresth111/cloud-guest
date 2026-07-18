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

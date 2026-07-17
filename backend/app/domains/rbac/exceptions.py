"""RBAC domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like auth's
``AuthServiceError`` hierarchy does -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class RBACError(CloudGuestError):
    """Base exception for RBAC domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class RoleNotFoundError(RBACError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Role not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class PermissionNotFoundError(RBACError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Permission not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class PermissionGroupNotFoundError(RBACError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Permission group not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class UserRoleAssignmentNotFoundError(RBACError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Role assignment not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateRoleError(RBACError):
    """A role with the same slug already exists in the same scope/organization."""

    def __init__(self, slug: str, organization_id: uuid.UUID | None) -> None:
        scope_desc = (
            f"organization {organization_id}" if organization_id else "global scope"
        )
        super().__init__(
            f"A role with slug '{slug}' already exists in {scope_desc}",
            status_code=status.HTTP_409_CONFLICT,
        )


class SystemRoleImmutableError(RBACError):
    """System roles cannot be renamed, deleted, or have their scope changed."""

    def __init__(self, role_name: str, action: str) -> None:
        super().__init__(
            f"System role '{role_name}' cannot be {action}",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class CircularRoleHierarchyError(RBACError):
    """A ``parent_role_id`` assignment would create a cycle in the role tree."""

    def __init__(self, role_id: uuid.UUID, parent_role_id: uuid.UUID) -> None:
        super().__init__(
            f"Assigning parent role {parent_role_id} to role {role_id} would create "
            "a circular role hierarchy",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidScopeAssignmentError(RBACError):
    """A role is being assigned/created at a scope it is not configured for."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class RoleEscalationError(RBACError):
    """An assigner tried to grant a role carrying permissions they don't hold."""

    def __init__(
        self, message: str = "Cannot assign a role with permissions you do not hold"
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class OverrideEscalationError(RBACError):
    """An assigner tried to grant a permission override they don't effectively hold."""

    def __init__(
        self,
        message: str = "Cannot grant a permission override you do not effectively hold",
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class RoleNotCloneableError(RBACError):
    """Only system roles or roles explicitly marked as templates may be cloned."""

    def __init__(self, role_name: str) -> None:
        super().__init__(
            f"Role '{role_name}' is not a system role or template and cannot be "
            "used as a cloning source",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class RoleInactiveError(RBACError):
    """An inactive role cannot be assigned to a user."""

    def __init__(self, role_name: str) -> None:
        super().__init__(
            f"Role '{role_name}' is deactivated and cannot be assigned",
            status_code=status.HTTP_409_CONFLICT,
        )


class CrossTenantAccessError(RBACError):
    """An operation attempted to read or mutate another organization's RBAC data."""

    def __init__(
        self, message: str = "Cannot access RBAC data belonging to another organization"
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class PermissionDeniedError(RBACError):
    """The authenticated user lacks the permission required for this action."""

    def __init__(self, permission_key: str, scope_description: str = "") -> None:
        message = f"Permission denied: '{permission_key}' is required"
        if scope_description:
            message += f" at {scope_description}"
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class RoleNotHeldError(RBACError):
    """The authenticated user lacks a required active role assignment."""

    def __init__(self, role_identifier: str) -> None:
        super().__init__(
            f"An active assignment of role '{role_identifier}' is required",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidScopeHeaderError(RBACError):
    """A scope header (e.g. ``X-Organization-Id``) did not contain a valid UUID."""

    def __init__(self, header_name: str) -> None:
        super().__init__(
            f"Header '{header_name}' must be a valid UUID",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class MissingScopeContextError(RBACError):
    """A required organization/location/router scope context was not supplied."""

    def __init__(self, scope_name: str) -> None:
        super().__init__(
            f"A valid {scope_name} context is required for this operation "
            f"(supply the X-{scope_name.title()}-Id header)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

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


class LastOrganizationOwnerError(RBACError):
    """An organization must always retain at least one active
    ``organization-owner`` role holder -- revoking (or, via the assign-then-
    revoke pattern the customer dashboard's "Manage Agents" role editor
    uses, downgrading) the sole remaining holder would leave the
    organization with nobody able to administer it, up to and including the
    holder itself losing every permission it needs to fix that (confirmed by
    live reproduction: doing this to a real account locked it out of its own
    ``users.read``/``roles.assign`` permissions immediately). A real
    ownership transfer -- assigning ``organization-owner`` to someone else
    first -- is required before this one can be revoked."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            "Cannot remove the organization's last Organization Owner -- "
            "assign another Organization Owner first, then remove this one "
            f"(organization {organization_id})",
            status_code=status.HTTP_409_CONFLICT,
        )


class LastGlobalAdminError(RBACError):
    """The platform must always retain at least one active, GLOBAL-scoped
    ``super-admin`` role holder -- revoking (or, via the assign-then-revoke
    downgrade pattern, downgrading) the sole remaining holder would leave the
    platform with nobody able to administer RBAC at all, the actor itself
    included. The internal-staff counterpart to ``LastOrganizationOwnerError``
    (which only guards per-organization ``organization-owner`` grants, never
    the GLOBAL staff grants the Master Console "Team & Access" page manages).
    A real handover -- granting another account Super Admin first -- is
    required before this one can be revoked."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot remove the platform's last Super Admin -- assign Super "
            "Admin to another account first, then remove this one",
            status_code=status.HTTP_409_CONFLICT,
        )


class CrossTenantAccessError(RBACError):
    """An operation attempted to read or mutate another organization's RBAC data."""

    def __init__(
        self, message: str = "Cannot access RBAC data belonging to another organization"
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


#: What ``AccessValidator._describe_scope`` renders for a GLOBAL-scope check.
#: Matched as a string rather than passing a ``ScopeType`` down, so this
#: module keeps its one-way dependency on ``enums`` unchanged and the
#: description stays the single thing both the audit row and the message are
#: built from.
GLOBAL_SCOPE_DESCRIPTION = "global scope"

#: Appended to a GLOBAL-scope denial.
#:
#: A permission held at ORGANIZATION scope can never satisfy a GLOBAL check,
#: whatever ``X-Organization-Id`` the caller sends (``ScopeResolver.satisfies``)
#: -- so for a venue account this refusal is permanent, and the bare original
#: message ("Permission denied: 'network_integrations.create' is required at
#: global scope") invited exactly the two wrong responses: switch organization
#: and retry, or open a ticket asking for the permission to be granted.
#:
#: It names no internal surface a venue account cannot reach, and no user,
#: role or organization -- a 403 that discloses the shape of the permission
#: model is its own problem. "A platform operator" is what the reader needs
#: and all of it.
GLOBAL_SCOPE_DENIAL_GUIDANCE = (
    ". This action is performed by a Wyfy Guest platform operator, not from a "
    "venue account -- selecting a different organization will not change "
    "that. If you need it done for your venue, ask your Wyfy Guest contact."
)


class PermissionDeniedError(RBACError):
    """The authenticated user lacks the permission required for this action."""

    def __init__(self, permission_key: str, scope_description: str = "") -> None:
        message = f"Permission denied: '{permission_key}' is required"
        if scope_description:
            message += f" at {scope_description}"
        if scope_description == GLOBAL_SCOPE_DESCRIPTION:
            message += GLOBAL_SCOPE_DENIAL_GUIDANCE
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


class UnspecifiedOrganizationScopeError(RBACError):
    """A GLOBAL-scoped caller named no organization and did not ask for all of them.

    Distinct from :class:`MissingScopeContextError`, which is what a *tenant*
    caller gets. This one is specifically the platform-admin case, and its
    message has to name both remedies because both are legitimate: a platform
    admin looking at one venue picks that venue, and a platform admin auditing
    the estate asks for every venue on purpose.

    Before this existed, that caller silently got every organization -- see
    ``app.domains.rbac.organization_scope`` for the report this produced.
    """

    def __init__(self) -> None:
        super().__init__(
            "This request did not say which organization it is about. Select an "
            "organization (send its id in the X-Organization-Id header), or ask "
            "for every organization explicitly (send X-Organization-Scope: all). "
            "Reading across organizations is never the default.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CrossOrganizationScopeDeniedError(RBACError):
    """A caller without a GLOBAL-scoped role asked to read across organizations.

    403 rather than a silent narrowing to their own tenant: a caller who
    believes they are looking at the whole estate and is actually looking at
    one tenant makes worse decisions than one who is told no.
    """

    def __init__(self) -> None:
        super().__init__(
            "Reading across organizations requires a platform-level (global) "
            "role. Scope this request to a single organization instead.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class SingleOrganizationRequiredError(RBACError):
    """A cross-organization request hit a route that only answers per-tenant.

    A usage summary, an invoice list or a per-venue report has no honest
    all-organizations answer -- summing one across fourteen tenants produces a
    number that is true of nobody. Refusing is better than inventing it.
    """

    def __init__(self) -> None:
        super().__init__(
            "This operation is about one organization, so it cannot be run "
            "across all of them. Select an organization (send its id in the "
            "X-Organization-Id header).",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

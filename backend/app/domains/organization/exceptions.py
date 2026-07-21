"""Organization domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
``AuthServiceError`` and ``RBACError`` do -- no route needs its own
try/except translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class OrganizationError(CloudGuestError):
    """Base exception for organization domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class OrganizationNotFoundError(OrganizationError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Organization not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateSlugError(OrganizationError):
    def __init__(self, slug: str) -> None:
        super().__init__(
            f"An organization with slug '{slug}' already exists",
            status_code=status.HTTP_409_CONFLICT,
        )


class NotAnMspOrganizationError(OrganizationError):
    """A ``parent_organization_id`` was set to an organization that is not
    an MSP-type container. Only MSP-type organizations may own children."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization {organization_id} is not an MSP-type organization "
            "and cannot have child organizations",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CircularOrganizationHierarchyError(OrganizationError):
    def __init__(
        self, organization_id: uuid.UUID, parent_organization_id: uuid.UUID
    ) -> None:
        super().__init__(
            f"Assigning parent organization {parent_organization_id} to organization "
            f"{organization_id} would create a circular hierarchy",
            status_code=status.HTTP_409_CONFLICT,
        )


class MspDowngradeWithChildrenError(OrganizationError):
    """An MSP-type organization with existing children cannot be changed to
    ``STANDARD`` -- its children would become orphaned MSP-less parents."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization {organization_id} has child organizations and cannot be "
            "changed away from the MSP type",
            status_code=status.HTTP_409_CONFLICT,
        )


class OrganizationArchivedError(OrganizationError):
    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization {organization_id} is archived and cannot be modified",
            status_code=status.HTTP_409_CONFLICT,
        )


class CrossOrganizationAccessError(OrganizationError):
    """A caller acting within organization A attempted to read/mutate
    organization B, where B is neither A itself nor a child of A."""

    def __init__(
        self,
        message: str = "Cannot access an organization outside your own scope",
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class OrganizationMembershipNotFoundError(OrganizationError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Organization membership not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateMembershipError(OrganizationError):
    def __init__(self, organization_id: uuid.UUID, user_id: uuid.UUID) -> None:
        super().__init__(
            f"User {user_id} already has an active or pending membership in "
            f"organization {organization_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class MembershipSuspendedError(OrganizationError):
    """A suspended member must be explicitly reactivated by an administrator
    -- they cannot simply be re-invited."""

    def __init__(self, organization_id: uuid.UUID, user_id: uuid.UUID) -> None:
        super().__init__(
            f"User {user_id}'s membership in organization {organization_id} is "
            "suspended and must be reactivated, not re-invited",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidMembershipStatusTransitionError(OrganizationError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class LastActiveMemberError(OrganizationError):
    """The last active member of an organization cannot be removed --
    every organization must retain at least one active member responsible
    for it."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Cannot remove the last active member of organization {organization_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidBrandingFieldError(OrganizationError):
    """A field in an org-wide branding update (see
    ``OrganizationService.update_branding``) failed validation --
    e.g. a malformed custom domain."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class OrganizationMembershipRequiredError(OrganizationError):
    """Raised by ``RequireOrganizationMembership``-style checks (see
    ``app.domains.rbac.dependencies.CurrentOrganization``) when the caller
    is not an active member of the organization named by the
    ``X-Organization-Id`` header."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"You are not an active member of organization {organization_id}",
            status_code=status.HTTP_403_FORBIDDEN,
        )

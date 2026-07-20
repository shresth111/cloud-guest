"""Policy domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "PolicyError",
    "PolicyNotFoundError",
    "PolicyVersionNotFoundError",
    "PolicyAssignmentNotFoundError",
    "CrossOrganizationPolicyAccessError",
    "InvalidPolicyVersionStatusTransitionError",
    "PolicyRulesValidationError",
    "PolicyAssignmentRequiresPublishedVersionError",
    "PolicyAssignmentScopeIdRequiredError",
    "PolicyAssignmentScopeIdNotAllowedError",
    "InvalidPolicyAssignmentScopeTypeError",
    "PolicyRollbackTargetNotPublishedError",
    "PolicyRollbackTargetMismatchError",
]


class PolicyError(CloudGuestError):
    """Base exception for Policy domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class PolicyNotFoundError(PolicyError):
    def __init__(self, policy_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Policy not found: {policy_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class PolicyVersionNotFoundError(PolicyError):
    def __init__(self, version_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Policy version not found: {version_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class PolicyAssignmentNotFoundError(PolicyError):
    def __init__(self, assignment_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Policy assignment not found: {assignment_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationPolicyAccessError(PolicyError):
    """A caller acting within organization A attempted to read/mutate a
    policy belonging to organization B -- mirrors
    ``app.domains.guest_teams.exceptions.CrossOrganizationGuestTeamAccessError``.
    Also raised when a non-platform (organization-scoped) caller attempts to
    create or mutate a platform-wide policy (``organization_id=None``) --
    only a caller with no ``requesting_organization_id`` at all (a
    platform-level caller, mirroring ``ScopeType.GLOBAL``) may own those."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a policy belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidPolicyVersionStatusTransitionError(PolicyError):
    """Raised when a requested status change is not a legal edge in
    ``constants.POLICY_VERSION_STATUS_TRANSITIONS`` -- covers publishing an
    already-published version."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition policy version from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class PolicyRulesValidationError(PolicyError):
    """The ``rules`` payload supplied to ``create_version`` does not match
    the Pydantic schema registered for this ``PolicyType`` in
    ``schemas.POLICY_RULE_SCHEMAS`` -- see that registry's own docstring for
    which types have a concrete schema vs. the generic passthrough."""

    def __init__(self, policy_type: str, detail: str) -> None:
        super().__init__(
            f"Invalid rules payload for policy type '{policy_type}': {detail}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class PolicyAssignmentRequiresPublishedVersionError(PolicyError):
    """A policy cannot be assigned to any scope until it has at least one
    ``PUBLISHED`` version -- an unpublished policy has no rules a resolver
    could honestly return."""

    def __init__(self, policy_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Policy {policy_id} has no published version and cannot be assigned",
            status_code=status.HTTP_409_CONFLICT,
        )


class PolicyAssignmentScopeIdRequiredError(PolicyError):
    def __init__(self, scope_type: str) -> None:
        super().__init__(
            f"scope_id is required for scope_type '{scope_type}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class PolicyAssignmentScopeIdNotAllowedError(PolicyError):
    def __init__(self) -> None:
        super().__init__(
            "scope_id must not be set for scope_type 'global'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidPolicyAssignmentScopeTypeError(PolicyError):
    """``scope_type`` is not one of ``app.domains.rbac.enums.ScopeType``'s
    values."""

    def __init__(self, scope_type: str) -> None:
        super().__init__(
            f"Invalid scope_type: '{scope_type}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class PolicyRollbackTargetNotPublishedError(PolicyError):
    """``rollback`` may only re-point ``Policy.current_version_id`` at a
    version that has itself already been published -- rolling back to a
    ``DRAFT`` version would silently activate rules nobody ever reviewed and
    published."""

    def __init__(self, version_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Policy version {version_id} is not published and cannot be "
            "rolled back to",
            status_code=status.HTTP_409_CONFLICT,
        )


class PolicyRollbackTargetMismatchError(PolicyError):
    """The version supplied to ``rollback`` does not belong to the policy
    being rolled back."""

    def __init__(self, policy_id: uuid.UUID | str, version_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Policy version {version_id} does not belong to policy {policy_id}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

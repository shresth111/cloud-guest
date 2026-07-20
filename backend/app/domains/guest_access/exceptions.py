"""Guest Access Control domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "GuestAccessError",
    "AccessRuleNotFoundError",
    "CrossOrganizationAccessRuleError",
    "TemporaryRuleRequiresExpiryError",
    "InvalidRuleExpiryError",
    "GuestAccessDeniedError",
]


class GuestAccessError(CloudGuestError):
    """Base exception for Guest Access Control domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class AccessRuleNotFoundError(GuestAccessError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Access rule not found: {rule_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationAccessRuleError(GuestAccessError):
    """A caller acting within organization A attempted to read/mutate an
    access rule belonging to organization B -- mirrors
    ``app.domains.guest.exceptions.CrossOrganizationGuestAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class TemporaryRuleRequiresExpiryError(GuestAccessError):
    """A ``rule_type=TEMPORARY`` rule was submitted with no ``expires_at``
    -- see ``constants.AccessRuleType.TEMPORARY``'s docstring for why this
    is rejected rather than silently treated as permanent."""

    def __init__(self) -> None:
        super().__init__(
            "A temporary access rule must include an expires_at",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidRuleExpiryError(GuestAccessError):
    def __init__(self) -> None:
        super().__init__(
            "expires_at must be in the future", status_code=status.HTTP_400_BAD_REQUEST
        )


class GuestAccessDeniedError(GuestAccessError):
    """Raised by ``AccessDecisionResolver``-driven enforcement (the
    optional hook composed into ``app.domains.guest.service.GuestService``
    -- see that module's own docstring for the composition) when the
    resolved decision for a login attempt is ``BLOCKLIST``. Carries the
    matched rule's ``reason`` (if any) so the caller can surface it exactly
    as ``app.domains.guest.exceptions.GuestBlockedError`` already does for
    the guest-level ``Guest.is_blocked`` flag."""

    def __init__(self, reason: str | None = None) -> None:
        message = "Access denied by an active guest access control rule"
        if reason:
            message += f": {reason}"
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)

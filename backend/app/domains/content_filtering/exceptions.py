"""Content Filtering domain exceptions.

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
    "ContentFilteringError",
    "ContentFilterRuleNotFoundError",
    "CrossOrganizationContentFilterRuleAccessError",
    "InvalidContentFilterValueError",
    "ContentFilterRuleAlreadyExistsError",
]


class ContentFilteringError(CloudGuestError):
    """Base exception for Content Filtering domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class ContentFilterRuleNotFoundError(ContentFilteringError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Content filter rule not found: {rule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationContentFilterRuleAccessError(ContentFilteringError):
    """Mirrors ``app.domains.firewall.exceptions
    .CrossOrganizationFirewallRuleAccessError``'s identical shape."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a content filter rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidContentFilterValueError(ContentFilteringError):
    """Raised when a rule's ``value`` is not a real, parseable instance of
    its own ``value_type`` -- not a real hostname for ``DOMAIN``, not a
    real IP/CIDR for ``IP_CIDR``."""

    def __init__(self, value_type: str, value: str) -> None:
        super().__init__(
            f"Invalid {value_type} value for a content filter rule: '{value}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class ContentFilterRuleAlreadyExistsError(ContentFilteringError):
    """A router may not hold two non-deleted rules for the same
    ``(value_type, value)`` pair -- mirrors ``app.domains
    .mac_authorization.exceptions.MacAuthorizationAlreadyExistsError``'s
    identical "avoid a redundant, device-duplicating row" reasoning."""

    def __init__(self, router_id: uuid.UUID, value_type: str, value: str) -> None:
        super().__init__(
            f"Router '{router_id}' already has a {value_type} content "
            f"filter rule for '{value}'",
            status_code=status.HTTP_409_CONFLICT,
        )

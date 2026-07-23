"""Support Tickets domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.guest_access.exceptions``'s identical style.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "SupportTicketError",
    "TicketNotFoundError",
    "InvalidTicketLocationError",
    "CrossOrganizationTicketAccessError",
    "OrganizationContextRequiredError",
]


class SupportTicketError(CloudGuestError):
    """Base exception for Support Tickets domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class TicketNotFoundError(SupportTicketError):
    def __init__(self, ticket_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Support ticket not found: {ticket_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvalidTicketLocationError(SupportTicketError):
    """The ``location_id`` supplied on ticket create does not belong to the
    ticket's own ``organization_id`` -- mirrors
    ``app.domains.location.service.LocationService``'s own
    ``_assert_organization_accessible`` cross-reference-validation
    posture, applied here to a location referenced *by* a ticket rather
    than the location itself."""

    def __init__(self) -> None:
        super().__init__(
            "location_id does not belong to this organization",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CrossOrganizationTicketAccessError(SupportTicketError):
    """A caller acting within organization A attempted to read/mutate a
    ticket belonging to organization B -- mirrors
    ``app.domains.guest_access.exceptions.CrossOrganizationAccessRuleError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a support ticket belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class OrganizationContextRequiredError(SupportTicketError):
    """Raised when a create request carries no ``X-Organization-Id``
    context (``CurrentOrganization`` returns ``None``) -- every
    ``SupportTicket`` belongs to exactly one organization
    (``organization_id`` is not nullable), mirroring
    ``app.domains.mac_authorization.exceptions.OrganizationRequiredError``'s
    identical rationale."""

    def __init__(self) -> None:
        super().__init__(
            "An X-Organization-Id header is required to create a support ticket",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

"""Assistant domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.support_tickets.exceptions``'s identical style.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "AssistantError",
    "ConversationNotFoundError",
    "CrossOrganizationConversationAccessError",
    "OrganizationContextRequiredError",
]


class AssistantError(CloudGuestError):
    """Base exception for Assistant domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class ConversationNotFoundError(AssistantError):
    def __init__(self, conversation_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Conversation not found: {conversation_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationConversationAccessError(AssistantError):
    """A caller attempted to read/mutate a conversation belonging to
    another organization, or to another user within the same
    organization -- this domain is strictly self-service (see
    ``service.py``'s module docstring), unlike
    ``app.domains.support_tickets`` where any org member's ticket is
    visible to a platform admin. Mirrors
    ``app.domains.support_tickets.exceptions
    .CrossOrganizationTicketAccessError``'s identical shape, just also
    covering the narrower same-org-different-user case."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a conversation that does not belong to you",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class OrganizationContextRequiredError(AssistantError):
    """Raised when a create request carries no ``X-Organization-Id``
    context (``CurrentOrganization`` returns ``None``) -- every
    ``AssistantConversation`` belongs to exactly one organization
    (``organization_id`` is not nullable), mirroring
    ``app.domains.support_tickets.exceptions
    .OrganizationContextRequiredError``'s identical rationale."""

    def __init__(self) -> None:
        super().__init__(
            "An X-Organization-Id header is required to start a conversation",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

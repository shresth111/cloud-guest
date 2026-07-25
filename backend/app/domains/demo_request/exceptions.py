"""Demo Request domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.support_tickets.exceptions``'s identical style.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = ["DemoRequestError", "DemoRequestNotFoundError"]


class DemoRequestError(CloudGuestError):
    """Base exception for Demo Request domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class DemoRequestNotFoundError(DemoRequestError):
    def __init__(self, demo_request_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Demo request not found: {demo_request_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

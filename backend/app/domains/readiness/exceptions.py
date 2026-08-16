"""Router Readiness Checklist domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "ReadinessError",
    "UnknownChecklistItemError",
]


class ReadinessError(CloudGuestError):
    """Base exception for Router Readiness Checklist domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class UnknownChecklistItemError(ReadinessError):
    def __init__(self, item_key: str) -> None:
        super().__init__(
            f"'{item_key}' is not a known readiness checklist item",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

"""Exceptions for the Events domain."""

from fastapi import status
from app.common.exceptions import CloudGuestError

class EventError(CloudGuestError):
    """Base exception for events domain errors."""
    def __init__(self, message: str, *, status_code: int = status.HTTP_400_BAD_REQUEST) -> None:
        super().__init__(message, status_code=status_code)

class EventNotFoundError(EventError):
    def __init__(self, event_id: object) -> None:
        super().__init__(
            f"Event not found: {event_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

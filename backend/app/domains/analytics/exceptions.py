"""Exceptions for the Analytics domain."""

from fastapi import status
from app.common.exceptions import CloudGuestError

class AnalyticsError(CloudGuestError):
    """Base exception for analytics domain errors."""
    def __init__(self, message: str, *, status_code: int = status.HTTP_400_BAD_REQUEST) -> None:
        super().__init__(message, status_code=status_code)

class AnalyticsAggregateNotFoundError(AnalyticsError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Analytics aggregate not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

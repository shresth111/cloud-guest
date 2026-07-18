"""Exceptions for the Monitoring domain."""

from fastapi import status
from app.common.exceptions import CloudGuestError

class MonitoringError(CloudGuestError):
    """Base exception for monitoring errors."""
    def __init__(self, message: str, *, status_code: int = status.HTTP_400_BAD_REQUEST) -> None:
        super().__init__(message, status_code=status_code)

class RouterMetricNotFoundError(MonitoringError):
    def __init__(self, metric_id: object) -> None:
        super().__init__(
            f"Router metric record not found: {metric_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

class InvalidMetricValueError(MonitoringError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

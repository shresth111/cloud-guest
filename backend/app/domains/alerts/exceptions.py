"""Exceptions for the Alerts domain."""

from fastapi import status
from app.common.exceptions import CloudGuestError

class AlertError(CloudGuestError):
    """Base exception for alerts domain errors."""
    def __init__(self, message: str, *, status_code: int = status.HTTP_400_BAD_REQUEST) -> None:
        super().__init__(message, status_code=status_code)

class AlertNotFoundError(AlertError):
    def __init__(self, alert_id: object) -> None:
        super().__init__(
            f"Alert not found: {alert_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

class AlertRuleNotFoundError(AlertError):
    def __init__(self, rule_id: object) -> None:
        super().__init__(
            f"Alert rule not found: {rule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

class AlertAlreadyResolvedError(AlertError):
    def __init__(self, alert_id: object) -> None:
        super().__init__(
            f"Alert {alert_id} is already resolved",
            status_code=status.HTTP_409_CONFLICT,
        )

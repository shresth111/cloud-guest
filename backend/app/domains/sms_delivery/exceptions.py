"""Exceptions for the SMS delivery report."""

from __future__ import annotations

from fastapi import status

from app.common.exceptions import CloudGuestError


class SmsDeliveryLocationAccessError(CloudGuestError):
    """A location-confined caller asked for a location outside their grants."""

    def __init__(
        self,
        message: str = "Cannot read SMS delivery for a location outside your scope",
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


__all__ = ["SmsDeliveryLocationAccessError"]

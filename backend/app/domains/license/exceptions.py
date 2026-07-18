"""Exceptions for the License domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class LicenseError(CloudGuestError):
    """Base exception for license errors."""


class LicenseNotFoundError(LicenseError):
    def __init__(self, key: str) -> None:
        super().__init__(
            f"License key {key} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class LicenseAlreadyActivatedError(LicenseError):
    def __init__(self, key: str) -> None:
        super().__init__(
            f"License key {key} is already activated",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class LicenseExpiredError(LicenseError):
    def __init__(self, key: str) -> None:
        super().__init__(
            f"License key {key} has expired",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class LicenseBindingMismatchError(LicenseError):
    def __init__(self, message: str) -> None:
        super().__init__(
            f"License binding mismatch: {message}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

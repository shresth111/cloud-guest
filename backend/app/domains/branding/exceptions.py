"""Exceptions for the Branding domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class BrandingError(CloudGuestError):
    """Base exception for branding errors."""


class BrandingNotFoundError(BrandingError):
    def __init__(self, key: str) -> None:
        super().__init__(
            f"Branding record not found for {key}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

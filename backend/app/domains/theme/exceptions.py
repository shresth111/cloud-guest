"""Exceptions for the Theme domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class ThemeError(CloudGuestError):
    """Base exception for theme errors."""


class ThemeNotFoundError(ThemeError):
    def __init__(self, key: str) -> None:
        super().__init__(
            f"Theme configurations not found for key: {key}",
            status_code=status.HTTP_404_NOT_FOUND,
        )

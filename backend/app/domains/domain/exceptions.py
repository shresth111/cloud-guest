"""Exceptions for the Custom Domains module."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class CustomDomainError(CloudGuestError):
    """Base exception for custom domain errors."""


class CustomDomainNotFoundError(CustomDomainError):
    def __init__(self, domain_name: str) -> None:
        super().__init__(
            f"Custom domain {domain_name} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CustomDomainLimitExceededError(CustomDomainError):
    def __init__(self) -> None:
        super().__init__(
            "Maximum number of custom domains has been reached.",
            status_code=status.HTTP_403_FORBIDDEN,
        )

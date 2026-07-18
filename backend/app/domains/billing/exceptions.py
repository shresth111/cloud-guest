"""Exceptions for the Billing domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class BillingError(CloudGuestError):
    """Base billing exception."""


class BillingProfileNotFoundError(BillingError):
    def __init__(self, organization_id: str) -> None:
        super().__init__(
            f"Billing profile not found for organization {organization_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class PaymentMethodFailedError(BillingError):
    def __init__(self, message: str) -> None:
        super().__init__(
            f"Payment method operation failed: {message}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

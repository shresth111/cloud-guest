"""Exceptions for the Payment domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class PaymentError(CloudGuestError):
    """Base exception for payment errors."""


class PaymentNotFoundError(PaymentError):
    def __init__(self, payment_id: str) -> None:
        super().__init__(
            f"Payment transaction with id {payment_id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class PaymentProcessingError(PaymentError):
    def __init__(self, message: str) -> None:
        super().__init__(
            f"Payment processing failed: {message}",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
        )


class CouponNotFoundError(PaymentError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"Coupon code '{code}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CouponExpiredError(PaymentError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"Coupon code '{code}' has expired",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidWebhookSignatureError(PaymentError):
    def __init__(self) -> None:
        super().__init__(
            "Invalid webhook signature",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

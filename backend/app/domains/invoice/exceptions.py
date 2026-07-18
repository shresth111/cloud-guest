"""Exceptions for the Invoice domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status


class InvoiceError(CloudGuestError):
    """Base exception for invoice errors."""


class InvoiceNotFoundError(InvoiceError):
    def __init__(self, invoice_id: str) -> None:
        super().__init__(
            f"Invoice with id {invoice_id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvoiceActionNotAllowedError(InvoiceError):
    def __init__(self, action: str, current_status: str) -> None:
        super().__init__(
            f"Cannot perform {action} on invoice that is {current_status}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

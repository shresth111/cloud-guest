"""Quotation domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.demo_request.exceptions``'s identical style.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "QuotationError",
    "QuotationNotFoundError",
    "QuotationHasNoLineItemsError",
]


class QuotationError(CloudGuestError):
    """Base exception for Quotation domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class QuotationNotFoundError(QuotationError):
    def __init__(self, quotation_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Quotation not found: {quotation_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class QuotationHasNoLineItemsError(QuotationError):
    def __init__(self) -> None:
        super().__init__(
            "A quotation must have at least one line item.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

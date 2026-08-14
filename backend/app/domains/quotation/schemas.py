"""Pydantic request/response schemas for the Quotation API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions --
see ``app.domains.demo_request.schemas``) and is wrapped in the project's
standard ``ApiResponse``/``build_response`` envelope by ``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

__all__ = [
    "QuotationLineItemInput",
    "QuotationCreateRequest",
    "QuotationLineItemResponse",
    "QuotationResponse",
    "QuotationListResponse",
]


# ============================================================================
# Request schemas
# ============================================================================


class QuotationLineItemInput(BaseModel):
    """One operator-typed line item -- a flat description/quantity/unit
    price row, the same shape as an invoice line item. An operator may
    prefill ``description``/``unit_price`` client-side from an existing
    ``GET /billing/plans`` row (a plan tier), but this schema carries no
    ``plan_id`` -- see ``models.py``'s own module docstring for why."""

    description: str = Field(..., min_length=1, max_length=500)
    quantity: Decimal = Field(default=Decimal("1"), gt=0)
    unit_price: Decimal = Field(..., ge=0)


class QuotationCreateRequest(BaseModel):
    """The Master console's "Generate & Send" form submission."""

    client_name: str = Field(..., min_length=1, max_length=255)
    client_email: EmailStr = Field(...)
    client_company_name: str = Field(..., min_length=1, max_length=255)
    line_items: list[QuotationLineItemInput] = Field(..., min_length=1)
    tax_percentage: Decimal = Field(default=Decimal("0"), ge=0, le=100)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    valid_until: datetime = Field(
        ..., description="Date this quotation's pricing stays valid until."
    )
    notes: str | None = Field(default=None, max_length=5_000)

    @field_validator("currency")
    @classmethod
    def uppercase_currency(cls, value: str) -> str:
        return value.upper()


# ============================================================================
# Response schemas
# ============================================================================


class QuotationLineItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    description: str
    quantity: Decimal
    unit_price: Decimal
    amount: Decimal


class QuotationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    quotation_number: str
    status: str
    client_name: str
    client_email: str
    client_company_name: str
    line_items: list[QuotationLineItemResponse]
    subtotal: Decimal
    tax_percentage: Decimal
    tax_amount: Decimal
    total_amount: Decimal
    currency: str
    valid_until: datetime
    notes: str | None
    sent_at: datetime | None
    email_error: str | None
    created_at: datetime
    updated_at: datetime


class QuotationListResponse(BaseModel):
    items: list[QuotationResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

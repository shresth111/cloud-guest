"""Pydantic schemas for the Invoice domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class InvoiceLineItem(BaseModel):
    description: str
    quantity: int = Field(1, ge=1)
    unit_price: float = Field(..., ge=0)
    amount: float


class InvoiceCreate(BaseModel):
    organization_id: uuid.UUID
    subscription_id: uuid.UUID | None = None
    subtotal: float = Field(..., ge=0)
    tax_rate: float = Field(0.18, ge=0)
    discount_amount: float = Field(0.0, ge=0)
    currency: str = Field("USD", min_length=3, max_length=3)
    line_items: list[InvoiceLineItem]


class CreditNoteCreate(BaseModel):
    invoice_id: uuid.UUID
    organization_id: uuid.UUID
    amount: float = Field(..., gt=0)
    reason: str | None = None


class CreditNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    invoice_id: uuid.UUID
    organization_id: uuid.UUID
    amount: float
    currency: str
    reason: str | None
    status: str
    created_at: datetime


class InvoiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    subscription_id: uuid.UUID | None
    invoice_number: str
    status: str
    issue_date: datetime
    due_date: datetime
    paid_at: datetime | None
    subtotal: float
    tax_amount: float
    tax_rate: float
    discount_amount: float
    total: float
    currency: str
    pdf_url: str | None
    invoice_metadata: dict
    created_at: datetime

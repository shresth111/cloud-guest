"""Pydantic schemas for the Payment domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class PaymentIntentCreate(BaseModel):
    organization_id: uuid.UUID
    subscription_id: uuid.UUID | None = None
    amount: float = Field(..., gt=0)
    currency: str = Field("USD", min_length=3, max_length=3)
    gateway: str = Field("stripe", pattern="^(stripe|razorpay|paypal)$")


class PaymentIntentResponse(BaseModel):
    client_secret: str
    gateway_reference: str
    amount: float
    currency: str


class CouponCreate(BaseModel):
    code: str = Field(..., min_length=3, max_length=50)
    discount_type: str = Field("percentage", pattern="^(percentage|fixed_amount)$")
    discount_value: float = Field(..., gt=0)
    currency: str = Field("USD", min_length=3, max_length=3)
    expires_at: datetime | None = None
    max_redemptions: int | None = Field(None, ge=1)


class CouponResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    discount_type: str
    discount_value: float
    currency: str
    active: bool
    expires_at: datetime | None
    max_redemptions: int | None
    redemptions_count: int
    created_at: datetime


class PaymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    subscription_id: uuid.UUID | None
    invoice_id: uuid.UUID | None
    gateway: str
    gateway_payment_intent_id: str | None
    gateway_charge_id: str | None
    amount: float
    currency: str
    tax_amount: float
    status: str
    refund_amount: float
    failure_reason: str | None
    card_brand: str | None
    card_last4: str | None
    created_at: datetime

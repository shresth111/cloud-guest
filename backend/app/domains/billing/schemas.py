"""Pydantic schemas for the Billing domain."""

from __future__ import annotations

import uuid
from typing import Any
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AddressSchema(BaseModel):
    line1: str | None = None
    line2: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None


class BillingProfileCreate(BaseModel):
    organization_id: uuid.UUID
    billing_email: EmailStr | None = None
    billing_phone: str | None = None
    billing_address: AddressSchema | None = None
    tax_id: str | None = None
    tax_id_type: str | None = None


class BillingProfileUpdate(BaseModel):
    billing_email: EmailStr | None = None
    billing_phone: str | None = None
    billing_address: AddressSchema | None = None
    tax_id: str | None = None
    tax_id_type: str | None = None
    payment_method_id: str | None = None
    card_brand: str | None = None
    card_last4: str | None = None


class BillingProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    customer_id: str | None
    payment_method_id: str | None
    card_brand: str | None
    card_last4: str | None
    billing_email: str | None
    billing_phone: str | None
    billing_address: dict[str, Any]
    tax_id: str | None
    tax_id_type: str | None

"""SQLAlchemy models for the Billing domain."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class BillingProfile(BaseModel):
    """Represents a customer billing profile containing integration references."""

    __tablename__ = "billing_profiles"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, index=True, nullable=False
    )
    
    # Stripe or Razorpay customer reference
    customer_id: Mapped[str | None] = mapped_column(String(100), unique=True, index=True, nullable=True)
    
    # Primary payment method
    payment_method_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    card_brand: Mapped[str | None] = mapped_column(String(50), nullable=True)
    card_last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    
    # Billing info
    billing_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    billing_phone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # Address and Tax details
    billing_address: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    tax_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tax_id_type: Mapped[str | None] = mapped_column(String(50), nullable=True)  # GST, VAT, EIN, etc.

"""SQLAlchemy models for the Payment domain."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Numeric, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class Payment(BaseModel):
    """Represents a payment transaction processed via external gateway (Stripe/Razorpay)."""

    __tablename__ = "payments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=True
    )
    invoice_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=True
    )

    gateway: Mapped[str] = mapped_column(String(50), nullable=False)  # stripe, razorpay, paypal
    gateway_payment_intent_id: Mapped[str | None] = mapped_column(String(150), unique=True, index=True, nullable=True)
    gateway_charge_id: Mapped[str | None] = mapped_column(String(150), unique=True, nullable=True)

    amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    tax_amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False, default=0.00)

    status: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # pending, succeeded, failed, refunded
    refund_amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False, default=0.00)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    card_brand: Mapped[str | None] = mapped_column(String(50), nullable=True)
    card_last4: Mapped[str | None] = mapped_column(String(4), nullable=True)


class Coupon(BaseModel):
    """Represents discount coupons or promo codes applicable to purchases."""

    __tablename__ = "coupons"

    code: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    discount_type: Mapped[str] = mapped_column(String(20), nullable=False)  # percentage, fixed_amount
    discount_value: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")

    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_redemptions: Mapped[int | None] = mapped_column(nullable=True)
    redemptions_count: Mapped[int] = mapped_column(default=0, nullable=False)

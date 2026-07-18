"""Service layer for the Payment domain."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Sequence

from .constants import PaymentStatus, PaymentGateway, DiscountType, DEFAULT_GST_RATE
from .exceptions import (
    CouponNotFoundError,
    PaymentNotFoundError,
    PaymentProcessingError,
)
from .models import Payment, Coupon
from .repository import PaymentRepositoryProtocol
from .validators import validate_coupon_eligibility


class PaymentService:
    def __init__(self, repository: PaymentRepositoryProtocol) -> None:
        self.repository = repository

    def calculate_tax(self, base_amount: float, tax_rate: float = DEFAULT_GST_RATE) -> float:
        """Calculate GST tax amount."""
        return round(base_amount * tax_rate, 2)

    async def create_payment_intent(
        self,
        organization_id: uuid.UUID,
        amount: float,
        currency: str = "USD",
        gateway: str = "stripe",
        subscription_id: uuid.UUID | None = None,
        invoice_id: uuid.UUID | None = None,
    ) -> dict:
        tax_amt = self.calculate_tax(amount)
        total_amt = amount + tax_amt

        # Mocking gateway interaction
        gateway_intent_id = f"pi_{uuid.uuid4().hex[:14]}"
        client_secret = f"secret_{uuid.uuid4().hex[:20]}"

        # Record payment intent in DB as pending
        payment_data = {
            "organization_id": organization_id,
            "subscription_id": subscription_id,
            "invoice_id": invoice_id,
            "gateway": gateway,
            "gateway_payment_intent_id": gateway_intent_id,
            "amount": total_amt,
            "currency": currency,
            "tax_amount": tax_amt,
            "status": PaymentStatus.PENDING.value,
        }
        await self.repository.create_payment(payment_data)

        return {
            "client_secret": client_secret,
            "gateway_reference": gateway_intent_id,
            "amount": total_amt,
            "currency": currency,
        }

    async def handle_successful_charge(
        self,
        gateway_intent_id: str,
        charge_id: str,
        brand: str | None = None,
        last4: str | None = None,
    ) -> Payment:
        payment = await self.repository.get_payment_by_intent(gateway_intent_id)
        if not payment:
            raise PaymentNotFoundError(gateway_intent_id)

        update_data = {
            "gateway_charge_id": charge_id,
            "status": PaymentStatus.SUCCEEDED.value,
            "card_brand": brand,
            "card_last4": last4,
            "updated_at": datetime.now(UTC),
        }
        return await self.repository.update_payment(payment, update_data)

    async def handle_failed_charge(
        self, gateway_intent_id: str, reason: str
    ) -> Payment:
        payment = await self.repository.get_payment_by_intent(gateway_intent_id)
        if not payment:
            raise PaymentNotFoundError(gateway_intent_id)

        update_data = {
            "status": PaymentStatus.FAILED.value,
            "failure_reason": reason,
            "updated_at": datetime.now(UTC),
        }
        return await self.repository.update_payment(payment, update_data)

    async def process_refund(
        self, payment_id: uuid.UUID, refund_amount: float | None = None
    ) -> Payment:
        payment = await self.repository.get_payment_by_id(payment_id)
        if not payment:
            raise PaymentNotFoundError(str(payment_id))

        amt_to_refund = refund_amount or payment.amount
        if amt_to_refund > payment.amount:
            raise PaymentProcessingError("Refund amount exceeds original charge.")

        update_data = {
            "status": PaymentStatus.REFUNDED.value,
            "refund_amount": amt_to_refund,
            "updated_at": datetime.now(UTC),
        }
        return await self.repository.update_payment(payment, update_data)

    async def create_coupon(self, coupon_data: dict) -> Coupon:
        return await self.repository.create_coupon(coupon_data)

    async def apply_coupon(self, code: str, order_amount: float) -> tuple[float, Coupon]:
        coupon = await self.repository.get_coupon_by_code(code)
        if not coupon:
            raise CouponNotFoundError(code)

        validate_coupon_eligibility(coupon)

        discount = 0.0
        if coupon.discount_type == DiscountType.PERCENTAGE.value:
            discount = round(order_amount * (coupon.discount_value / 100.0), 2)
        else:
            discount = min(coupon.discount_value, order_amount)

        # Update redemption count
        await self.repository.update_coupon(
            coupon, {"redemptions_count": coupon.redemptions_count + 1}
        )

        final_amount = max(0.0, order_amount - discount)
        return final_amount, coupon

    async def list_payments(self, organization_id: uuid.UUID) -> Sequence[Payment]:
        return await self.repository.list_payments_by_org(organization_id)

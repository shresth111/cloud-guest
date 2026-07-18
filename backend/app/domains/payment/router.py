"""API Router for the Payment domain."""

import uuid
from typing import Sequence
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from .dependencies import get_payment_service
from .schemas import (
    CouponCreate,
    CouponResponse,
    PaymentIntentCreate,
    PaymentIntentResponse,
    PaymentResponse,
)
from .service import PaymentService

router = APIRouter()


@router.post(
    "/payments/intents", response_model=PaymentIntentResponse, tags=["Payments"]
)
async def create_payment_intent(
    payload: PaymentIntentCreate,
    service: PaymentService = Depends(get_payment_service),
):
    """Generate a payment intent with calculated GST taxes."""
    return await service.create_payment_intent(
        organization_id=payload.organization_id,
        amount=payload.amount,
        currency=payload.currency,
        gateway=payload.gateway,
        subscription_id=payload.subscription_id,
    )


@router.get(
    "/payments/organization/{organization_id}",
    response_model=Sequence[PaymentResponse],
    tags=["Payments"],
)
async def list_payments(
    organization_id: uuid.UUID,
    service: PaymentService = Depends(get_payment_service),
):
    """Retrieve the payment history for an organization."""
    return await service.list_payments(organization_id)


@router.post(
    "/payments/{payment_id}/refund", response_model=PaymentResponse, tags=["Payments"]
)
async def process_refund(
    payment_id: uuid.UUID,
    refund_amount: float | None = None,
    service: PaymentService = Depends(get_payment_service),
):
    """Refund a previously successful transaction."""
    return await service.process_refund(payment_id, refund_amount)


@router.post(
    "/coupons",
    response_model=CouponResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Coupons"],
)
async def create_coupon(
    payload: CouponCreate, service: PaymentService = Depends(get_payment_service)
):
    """Create a new discount coupon."""
    return await service.create_coupon(payload.model_dump())


# --- Webhook Listeners -----------------------------------------------------


@router.post("/payments/webhooks/stripe", tags=["Webhooks"])
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(None),
    service: PaymentService = Depends(get_payment_service),
):
    """Handle Stripe incoming webhooks for payments, cancellations, and renewals."""
    payload = await request.json()
    event_type = payload.get("type")

    if event_type == "payment_intent.succeeded":
        intent_id = payload["data"]["object"]["id"]
        charge_id = payload["data"]["object"].get("latest_charge")
        brand = payload["data"]["object"].get("charges", {}).get("data", [{}])[0].get("payment_method_details", {}).get("card", {}).get("brand")
        last4 = payload["data"]["object"].get("charges", {}).get("data", [{}])[0].get("payment_method_details", {}).get("card", {}).get("last4")
        await service.handle_successful_charge(intent_id, charge_id or f"ch_{uuid.uuid4().hex[:10]}", brand, last4)
    elif event_type == "payment_intent.payment_failed":
        intent_id = payload["data"]["object"]["id"]
        reason = payload["data"]["object"].get("last_payment_error", {}).get("message", "Unknown error")
        await service.handle_failed_charge(intent_id, reason)

    return {"status": "received"}


@router.post("/payments/webhooks/razorpay", tags=["Webhooks"])
async def razorpay_webhook(
    request: Request,
    x_razorpay_signature: str | None = Header(None),
    service: PaymentService = Depends(get_payment_service),
):
    """Handle Razorpay incoming webhooks for payments, renewals, and refunds."""
    payload = await request.json()
    event = payload.get("event")

    if event == "payment.captured":
        payment_id = payload["payload"]["payment"]["entity"]["id"]
        order_id = payload["payload"]["payment"]["entity"]["order_id"]
        await service.handle_successful_charge(order_id, payment_id)
    elif event == "payment.failed":
        order_id = payload["payload"]["payment"]["entity"]["order_id"]
        reason = payload["payload"]["payment"]["entity"].get("error_description", "Unknown error")
        await service.handle_failed_charge(order_id, reason)

    return {"status": "received"}

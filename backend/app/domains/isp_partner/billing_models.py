"""Phase 1b tables: service control (ADDENDUM_01 §A) and ISP billing
(ADDENDUM_01 §B.3 + ADDENDUM_03 Part A). New tables in our own domain only.

Amounts are integer paise. Invoice, credit-note and receipt numbers come
from ``isp_invoice_sequences`` under a row lock in the issuing transaction,
so a rollback leaves no gap.

``isp_invoices`` is the one invoice table for both bill-to kinds
(ADDENDUM_03 §2). In 1b only ``bill_to_kind='customer'`` exists; Part B adds
``subscriber_id`` (with ADDENDUM_02's subscribers) and extends the check
constraint.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


def _org_fk(*, nullable: bool = False, ondelete: str | None = None) -> Any:
    return mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete=ondelete),
        nullable=nullable,
    )


# ============================================================================
# Service control
# ============================================================================


class IspCustomerServiceState(BaseModel):
    """One row per customer that was ever suspended; no row = ``active``."""

    __tablename__ = "isp_customer_service_state"

    isp_organization_id: Mapped[uuid.UUID] = _org_fk()
    customer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        unique=True,
    )
    #: active | suspend_pending | suspended | resume_pending
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    show_suspended_page: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(100), nullable=True)
    idempotent_response: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    warnings: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    last_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_isp_customer_service_state_isp", "isp_organization_id"),
        Index("ix_isp_customer_service_state_state", "state"),
    )


class IspServiceAction(BaseModel):
    """One step of a suspend or resume for one router."""

    __tablename__ = "isp_service_actions"

    state_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_customer_service_state.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: which transition produced this step: suspend | resume
    transition: Mapped[str] = mapped_column(String(10), nullable=False)
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id"), nullable=True
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id"), nullable=True
    )
    nas_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("radius_nas_clients.id"), nullable=True
    )
    #: nas_disable | kick_sessions | portal_suspended_page | nas_activate |
    #: portal_restore
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    #: pending | done | skipped | failed | cancelled
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    prior_state: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index("ix_isp_service_actions_state_id", "state_id"),
        Index("ix_isp_service_actions_status", "status"),
    )


# ============================================================================
# Billing
# ============================================================================


class IspBillingSettings(BaseModel):
    __tablename__ = "isp_billing_settings"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, unique=True
    )
    legal_name: Mapped[str] = mapped_column(String(255), nullable=False)
    gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    state_code: Mapped[str] = mapped_column(String(2), nullable=False)
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    invoice_prefix: Mapped[str] = mapped_column(
        String(4), nullable=False, default="INV", server_default="INV"
    )
    credit_note_prefix: Mapped[str] = mapped_column(
        String(4), nullable=False, default="CN", server_default="CN"
    )
    receipt_prefix: Mapped[str] = mapped_column(
        String(12), nullable=False, default="RCT", server_default="RCT"
    )
    gst_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    gst_rate_bp: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1800, server_default="1800"
    )
    sac_code: Mapped[str] = mapped_column(
        String(8), nullable=False, default="998422", server_default="998422"
    )
    upi_vpa: Mapped[str | None] = mapped_column(String(100), nullable=True)
    payee_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    default_due_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=7, server_default="7"
    )
    grace_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=7, server_default="7"
    )
    auto_suspend_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    auto_suspend_after_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    coupon_invoice_on_activation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    reminder_days_before_expiry: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, server_default="3"
    )
    invoice_footer: Mapped[str | None] = mapped_column(Text, nullable=True)


class IspCustomerBilling(BaseModel):
    __tablename__ = "isp_customer_billing"

    customer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, unique=True
    )
    isp_organization_id: Mapped[uuid.UUID] = _org_fk()
    plan_name: Mapped[str] = mapped_column(String(100), nullable=False)
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    price_includes_gst: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: monthly | quarterly | half_yearly | yearly
    billing_cycle: Mapped[str] = mapped_column(String(16), nullable=False)
    anchor_day: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    next_invoice_date: Mapped[date] = mapped_column(Date, nullable=False)
    gst_applicable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    place_of_supply_state_code: Mapped[str | None] = mapped_column(
        String(2), nullable=True
    )
    buyer_gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_isp_customer_billing_isp", "isp_organization_id"),)


class IspZone(BaseModel):
    __tablename__ = "isp_zones"

    isp_organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_zones_isp_name",
            "isp_organization_id",
            text("lower(name)"),
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspInvoiceSequence(BaseModel):
    __tablename__ = "isp_invoice_sequences"

    isp_organization_id: Mapped[uuid.UUID] = _org_fk()
    #: invoice | credit_note | receipt
    series: Mapped[str] = mapped_column(String(16), nullable=False)
    #: ``25-26``; ``----`` for a series that never resets
    fy: Mapped[str] = mapped_column(String(5), nullable=False)
    next_value: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index(
            "uq_isp_invoice_sequences_key",
            "isp_organization_id",
            "series",
            "fy",
            unique=True,
        ),
    )


class IspInvoice(BaseModel):
    __tablename__ = "isp_invoices"

    display_id: Mapped[int] = mapped_column(
        BigInteger, Identity(always=False), nullable=False, unique=True
    )
    isp_organization_id: Mapped[uuid.UUID] = _org_fk()
    #: invoice | credit_note
    doc_type: Mapped[str] = mapped_column(
        String(12), nullable=False, default="invoice", server_default="invoice"
    )
    bill_to_kind: Mapped[str] = mapped_column(
        String(12), nullable=False, default="customer", server_default="customer"
    )
    customer_organization_id: Mapped[uuid.UUID | None] = _org_fk(nullable=True)
    #: Part B: set for bill_to_kind='subscriber'; customer_organization_id is
    #: then the subscriber's venue (scoping + confinement), never billed.
    subscriber_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_subscribers.id"), nullable=True
    )
    bill_to_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    circuit_id_snapshot: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fy: Mapped[str] = mapped_column(String(5), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    number: Mapped[str] = mapped_column(String(16), nullable=False)
    #: manual | cycle | recharge | renewal | coupon
    invoice_kind: Mapped[str] = mapped_column(String(12), nullable=False)
    source_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    issue_date: Mapped[date] = mapped_column(Date, nullable=False)
    due_date: Mapped[date] = mapped_column(Date, nullable=False)
    period_start: Mapped[date | None] = mapped_column(Date, nullable=True)
    period_end: Mapped[date | None] = mapped_column(Date, nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    bill_to_name: Mapped[str] = mapped_column(String(255), nullable=False)
    bill_to_gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    bill_to_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    place_of_supply_state_code: Mapped[str | None] = mapped_column(
        String(2), nullable=True
    )
    seller_state_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_zones.id"), nullable=True
    )
    po_number: Mapped[str | None] = mapped_column(String(40), nullable=True)
    gst_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    taxable_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cgst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sgst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    igst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    paid_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    credit_noted_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    credit_note_for_invoice_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_invoices.id"), nullable=True
    )
    #: issued | partially_paid | paid | cancelled
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    cancelled_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_invoices_series",
            "isp_organization_id",
            "doc_type",
            "fy",
            "seq",
            unique=True,
        ),
        Index(
            "uq_isp_invoices_source_key",
            "isp_organization_id",
            "source_key",
            unique=True,
            postgresql_where=text("source_key IS NOT NULL"),
        ),
        Index(
            "ix_isp_invoices_isp_customer",
            "isp_organization_id",
            "customer_organization_id",
        ),
        Index("ix_isp_invoices_issue_date", "isp_organization_id", "issue_date"),
        Index("ix_isp_invoices_subscriber", "subscriber_id"),
        CheckConstraint(
            "bill_to_kind = 'customer' AND customer_organization_id IS NOT NULL"
            " OR bill_to_kind = 'subscriber' AND subscriber_id IS NOT NULL",
            name="bill_to",
        ),
    )


class IspInvoiceLine(BaseModel):
    __tablename__ = "isp_invoice_lines"

    invoice_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_invoices.id"), nullable=False
    )
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    sac_code: Mapped[str] = mapped_column(String(8), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    unit_amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    price_includes_gst: Mapped[bool] = mapped_column(Boolean, nullable=False)
    taxable_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cgst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sgst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    igst_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    period_from: Mapped[date | None] = mapped_column(Date, nullable=True)
    period_to: Mapped[date | None] = mapped_column(Date, nullable=True)
    package_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_packages.id"), nullable=True
    )

    __table_args__ = (Index("ix_isp_invoice_lines_invoice", "invoice_id"),)


class IspPayment(BaseModel):
    __tablename__ = "isp_payments"

    isp_organization_id: Mapped[uuid.UUID] = _org_fk()
    customer_organization_id: Mapped[uuid.UUID | None] = _org_fk(nullable=True)
    subscriber_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_subscribers.id"), nullable=True
    )
    coupon_batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_coupon_batches.id"), nullable=True
    )
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: amount not allocated to any invoice (advance / credit)
    unallocated_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    #: cash | upi | bank_transfer | online | prepaid_coupon
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    recorded_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    receipt_fy: Mapped[str] = mapped_column(String(5), nullable=False)
    receipt_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    receipt_number: Mapped[str] = mapped_column(String(32), nullable=False)
    #: confirmed | voided
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    voided_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    gateway_payment_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway_link_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Client-supplied ``Idempotency-Key``: a repeat returns the first payment.
    idempotency_key: Mapped[str | None] = mapped_column(String(100), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_payments_idempotency",
            "isp_organization_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index(
            "uq_isp_payments_receipt",
            "isp_organization_id",
            "receipt_fy",
            "receipt_seq",
            unique=True,
        ),
        Index(
            "uq_isp_payments_gateway_payment",
            "isp_organization_id",
            "gateway_payment_id",
            unique=True,
            postgresql_where=text("gateway_payment_id IS NOT NULL"),
        ),
        Index(
            "ix_isp_payments_isp_customer",
            "isp_organization_id",
            "customer_organization_id",
        ),
        Index("ix_isp_payments_subscriber", "subscriber_id"),
    )


class IspPaymentAllocation(BaseModel):
    __tablename__ = "isp_payment_allocations"

    payment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_payments.id"), nullable=False
    )
    invoice_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_invoices.id"), nullable=False
    )
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (
        Index("ix_isp_payment_allocations_payment", "payment_id"),
        Index("ix_isp_payment_allocations_invoice", "invoice_id"),
        CheckConstraint("amount_paise > 0", name="positive"),
    )


class IspInvoiceReminder(BaseModel):
    __tablename__ = "isp_invoice_reminders"

    invoice_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_invoices.id"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    sent_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False)

    __table_args__ = (Index("ix_isp_invoice_reminders_invoice", "invoice_id"),)


BILLING_TABLES = (
    "isp_customer_service_state",
    "isp_service_actions",
    "isp_billing_settings",
    "isp_customer_billing",
    "isp_zones",
    "isp_invoice_sequences",
    "isp_invoices",
    "isp_invoice_lines",
    "isp_payments",
    "isp_payment_allocations",
    "isp_invoice_reminders",
)

__all__ = [
    "BILLING_TABLES",
    "IspBillingSettings",
    "IspCustomerBilling",
    "IspCustomerServiceState",
    "IspInvoice",
    "IspInvoiceLine",
    "IspInvoiceReminder",
    "IspInvoiceSequence",
    "IspPayment",
    "IspPaymentAllocation",
    "IspServiceAction",
    "IspZone",
]

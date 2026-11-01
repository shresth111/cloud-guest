"""JAZE-4 (ADDENDUM_05 J7/J9/J10/J14/J15/J23 + security deposits): new
ISP-owned tables only. Nothing here alters a pre-ISP table, and every row is
keyed by the ISP organization so ``IspScope`` / ``isp_org_id`` filters apply.

Amounts are integer paise, like the rest of ISP billing.

* ``isp_invoice_templates``: one row per ISP. Bank remittance details and
  the extra header/footer fields printed on its invoices.
* ``isp_billing_products``: the ISP's catalogue of billable items (bandwidth,
  static IP, installation, other), each with its SAC code (default 998422).
* ``isp_package_billing``: the billing plan bound to a package (prepaid or
  postpaid, chargeable duration, invoice description).
* ``isp_static_ip_leases``: a recurring static-IP rental per subscriber or
  customer, billed by ``bill_static_ip_leases``.
* ``isp_security_deposits``: collect / refund / forfeit entries per
  subscriber (or customer). The balance is the sum.
* ``isp_billing_contacts``: an alternate billing email per subscriber or
  customer (invoice email to primary / alternate / both).
* ``isp_automation_settings``: per-ISP WhatsApp automation and Telegram alert
  settings. The bot token is encrypted (the marketing provider key).
* ``isp_message_log``: every outbound automated or operator-sent message
  (email / WhatsApp / Telegram). The recipient is stored masked.
* ``isp_alert_device_state``: Telegram DOWN/UP debounce state per device.
* ``isp_pay_links``: short tokens for the public "pay this invoice" page.
* ``isp_zone_profiles`` / ``isp_zone_ledger_entries``: the labels-only zone
  (franchise) ledger. A zone has NO login, NO organization and NO routers;
  it is a label on customers/subscribers/invoices. Pending founder
  confirmation (D6 excluded a franchise hierarchy).
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
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


def _fk(target: str, *, nullable: bool = False) -> Any:
    return mapped_column(UUID(as_uuid=True), ForeignKey(target), nullable=nullable)


class IspInvoiceTemplate(BaseModel):
    __tablename__ = "isp_invoice_templates"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    bank_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    bank_account_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    bank_account_number: Mapped[str | None] = mapped_column(String(34), nullable=True)
    bank_ifsc: Mapped[str | None] = mapped_column(String(11), nullable=True)
    bank_branch: Mapped[str | None] = mapped_column(String(100), nullable=True)
    website: Mapped[str | None] = mapped_column(String(200), nullable=True)
    care_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    care_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pan: Mapped[str | None] = mapped_column(String(10), nullable=True)
    licence_number: Mapped[str | None] = mapped_column(String(60), nullable=True)
    terms: Mapped[str | None] = mapped_column(Text, nullable=True)
    show_bank_details: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    show_zone_operator: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    __table_args__ = (
        Index(
            "uq_isp_invoice_templates_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspBillingProduct(BaseModel):
    __tablename__ = "isp_billing_products"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: bandwidth | static_ip | installation | other
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    sac_code: Mapped[str] = mapped_column(
        String(8), nullable=False, default="998422", server_default="998422"
    )
    default_amount_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    price_includes_gst: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    __table_args__ = (
        Index(
            "uq_isp_billing_products_name",
            "isp_organization_id",
            text("lower(name)"),
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        CheckConstraint(
            "kind IN ('bandwidth','static_ip','installation','other')",
            name="kind",
        ),
    )


class IspPackageBilling(BaseModel):
    __tablename__ = "isp_package_billing"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    package_id: Mapped[uuid.UUID] = _fk("isp_packages.id")
    #: prepaid | postpaid
    plan_kind: Mapped[str] = mapped_column(String(10), nullable=False)
    #: days | months
    chargeable_unit: Mapped[str] = mapped_column(String(8), nullable=False)
    chargeable_count: Mapped[int] = mapped_column(Integer, nullable=False)
    invoice_description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product_id: Mapped[uuid.UUID | None] = _fk("isp_billing_products.id", nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_package_billing_package",
            "package_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        CheckConstraint("plan_kind IN ('prepaid','postpaid')", name="plan_kind"),
        CheckConstraint("chargeable_unit IN ('days','months')", name="unit"),
        CheckConstraint("chargeable_count BETWEEN 1 AND 366", name="count"),
    )


class IspStaticIpLease(BaseModel):
    __tablename__ = "isp_static_ip_leases"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: the venue (scoping/confinement); for a customer lease, the billed org
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    monthly_amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    price_includes_gst: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    active_since: Mapped[date] = mapped_column(Date, nullable=False)
    active_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    #: last day already invoiced (inclusive); NULL = never billed
    billed_through: Mapped[date | None] = mapped_column(Date, nullable=True)
    #: active | ended
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_static_ip_leases_active_ip",
            "isp_organization_id",
            "ip_address",
            unique=True,
            postgresql_where=text("status = 'active' AND deleted_at IS NULL"),
        ),
        Index("ix_isp_static_ip_leases_subscriber", "subscriber_id"),
        CheckConstraint("status IN ('active','ended')", name="status"),
    )


class IspSecurityDeposit(BaseModel):
    __tablename__ = "isp_security_deposits"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    #: collect | refund | forfeit
    entry_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    #: ont | router | stb | other
    item: Mapped[str] = mapped_column(String(8), nullable=False)
    item_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: cash | upi | bank_transfer | adjustment
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_isp_security_deposits_subscriber", "subscriber_id"),
        Index(
            "ix_isp_security_deposits_isp_customer",
            "isp_organization_id",
            "customer_organization_id",
        ),
        CheckConstraint("amount_paise > 0", name="positive"),
        CheckConstraint("entry_kind IN ('collect','refund','forfeit')", name="kind"),
    )


class IspBillingContact(BaseModel):
    __tablename__ = "isp_billing_contacts"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: customer | subscriber
    subject_kind: Mapped[str] = mapped_column(String(10), nullable=False)
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alternate_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    alternate_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    exclude_from_reminders: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    __table_args__ = (
        Index(
            "uq_isp_billing_contacts_subject",
            "isp_organization_id",
            "subject_kind",
            "subject_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspAutomationSettings(BaseModel):
    __tablename__ = "isp_automation_settings"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    whatsapp_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    #: {trigger: {"template_name": str, "language": str}}
    whatsapp_templates: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    pre_expiry_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=2, server_default="2"
    )
    unpaid_reminder_after_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    telegram_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    telegram_bot_token_encrypted: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    telegram_bot_token_hint: Mapped[str | None] = mapped_column(
        String(12), nullable=True
    )
    telegram_chat_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telegram_debounce_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, server_default="3"
    )
    telegram_include_aps: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    __table_args__ = (
        Index(
            "uq_isp_automation_settings_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspMessageLog(BaseModel):
    __tablename__ = "isp_message_log"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: email | whatsapp | telegram
    channel: Mapped[str] = mapped_column(String(10), nullable=False)
    #: pre_expiry | unpaid | receipt | renewal | invoice_email | device_alert | test
    trigger: Mapped[str] = mapped_column(String(16), nullable=False)
    recipient_masked: Mapped[str] = mapped_column(String(64), nullable=False)
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True
    )
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    invoice_id: Mapped[uuid.UUID | None] = _fk("isp_invoices.id", nullable=True)
    payment_id: Mapped[uuid.UUID | None] = _fk("isp_payments.id", nullable=True)
    summary: Mapped[str] = mapped_column(String(300), nullable=False)
    #: queued | sent | failed | skipped
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    notification_delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    #: one message per (trigger, subject, period); a repeat run skips
    dedupe_key: Mapped[str | None] = mapped_column(String(160), nullable=True)

    __table_args__ = (
        Index("ix_isp_message_log_isp_created", "isp_organization_id", "created_at"),
        Index(
            "uq_isp_message_log_dedupe",
            "isp_organization_id",
            "dedupe_key",
            unique=True,
            postgresql_where=text("dedupe_key IS NOT NULL"),
        ),
    )


class IspAlertDeviceState(BaseModel):
    __tablename__ = "isp_alert_device_state"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: router | ap
    device_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    #: up | down
    observed_status: Mapped[str] = mapped_column(String(4), nullable=False)
    observed_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    notified_status: Mapped[str | None] = mapped_column(String(4), nullable=True)
    notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_alert_device_state_device",
            "isp_organization_id",
            "device_kind",
            "device_id",
            unique=True,
        ),
    )


class IspPayLink(BaseModel):
    __tablename__ = "isp_pay_links"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    invoice_id: Mapped[uuid.UUID] = _fk("isp_invoices.id")
    token: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    open_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        Index("uq_isp_pay_links_token", "token", unique=True),
        Index("ix_isp_pay_links_invoice", "invoice_id"),
    )


class IspZoneProfile(BaseModel):
    __tablename__ = "isp_zone_profiles"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")
    contact_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    pincode: Mapped[str | None] = mapped_column(String(6), nullable=True)
    gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    pan: Mapped[str | None] = mapped_column(String(10), nullable=True)
    operator_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    operator_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: zone's share of collections, basis points (5000 = 50 %)
    revenue_share_bp: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    credit_limit_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    min_balance_paise: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    #: TDS u/s 194H on the zone's commission, basis points (200 = 2 %)
    tds_rate_bp: Mapped[int] = mapped_column(
        Integer, nullable=False, default=200, server_default="200"
    )

    __table_args__ = (
        Index(
            "uq_isp_zone_profiles_zone",
            "zone_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        CheckConstraint("revenue_share_bp BETWEEN 0 AND 10000", name="share"),
        CheckConstraint("credit_limit_paise >= 0", name="credit"),
        CheckConstraint("tds_rate_bp BETWEEN 0 AND 10000", name="tds"),
    )


class IspZoneLedgerEntry(BaseModel):
    __tablename__ = "isp_zone_ledger_entries"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")
    #: add (deposit received) | reduce (debit) | credit_limit (limit change,
    #: amount 0, detail carries old/new)
    entry_kind: Mapped[str] = mapped_column(String(12), nullable=False)
    #: signed: + add, - reduce, 0 credit_limit
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    balance_after_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_isp_zone_ledger_zone_time", "zone_id", "occurred_at"),
        CheckConstraint("entry_kind IN ('add','reduce','credit_limit')", name="kind"),
    )


FINANCE_TABLES = (
    "isp_invoice_templates",
    "isp_billing_products",
    "isp_package_billing",
    "isp_static_ip_leases",
    "isp_security_deposits",
    "isp_billing_contacts",
    "isp_automation_settings",
    "isp_message_log",
    "isp_alert_device_state",
    "isp_pay_links",
    "isp_zone_profiles",
    "isp_zone_ledger_entries",
)

__all__ = [
    "FINANCE_TABLES",
    "IspAlertDeviceState",
    "IspAutomationSettings",
    "IspBillingContact",
    "IspBillingProduct",
    "IspInvoiceTemplate",
    "IspMessageLog",
    "IspPackageBilling",
    "IspPayLink",
    "IspSecurityDeposit",
    "IspStaticIpLease",
    "IspZoneLedgerEntry",
    "IspZoneProfile",
]

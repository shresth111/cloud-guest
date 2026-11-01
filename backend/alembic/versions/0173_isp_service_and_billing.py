"""ISP Phase 1b: service control (suspend cuts internet) and ISP billing.

ADDENDUM_01 §A/§B.3 + ADDENDUM_03 Part A. Additive: eleven new tables in the
ISP partner domain, plus one nullable column (zone_id) on our OWN Phase 1
table isp_customer_profiles (ADDENDUM_03 §10 allows columns on our own
tables). No pre-ISP table is altered; every FK lives on our tables.
downgrade drops exactly these and the one column.

Revision ID: 0173_isp_service_and_billing
Revises: 0172_create_isp_partner_tables
Create Date: 2026-10-22
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0173_isp_service_and_billing"
down_revision = "0172_create_isp_partner_tables"
branch_labels = None
depends_on = None

TABLES = (
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


def upgrade() -> None:
    op.create_table(
        "isp_billing_settings",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("legal_name", sa.String(length=255), nullable=False),
        sa.Column("gstin", sa.String(length=15), nullable=True),
        sa.Column("state_code", sa.String(length=2), nullable=False),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column(
            "invoice_prefix", sa.String(length=4), server_default="INV", nullable=False
        ),
        sa.Column(
            "credit_note_prefix",
            sa.String(length=4),
            server_default="CN",
            nullable=False,
        ),
        sa.Column(
            "receipt_prefix", sa.String(length=12), server_default="RCT", nullable=False
        ),
        sa.Column(
            "gst_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("gst_rate_bp", sa.Integer(), server_default="1800", nullable=False),
        sa.Column(
            "sac_code", sa.String(length=8), server_default="998422", nullable=False
        ),
        sa.Column("upi_vpa", sa.String(length=100), nullable=True),
        sa.Column("payee_name", sa.String(length=100), nullable=True),
        sa.Column("default_due_days", sa.Integer(), server_default="7", nullable=False),
        sa.Column("grace_days", sa.Integer(), server_default="7", nullable=False),
        sa.Column(
            "auto_suspend_enabled",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("auto_suspend_after_days", sa.Integer(), nullable=True),
        sa.Column(
            "coupon_invoice_on_activation",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "reminder_days_before_expiry",
            sa.Integer(),
            server_default="3",
            nullable=False,
        ),
        sa.Column("invoice_footer", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_billing_settings_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_billing_settings")),
        sa.UniqueConstraint(
            "isp_organization_id",
            name=op.f("uq_isp_billing_settings_isp_organization_id"),
        ),
    )
    op.create_index(
        op.f("ix_isp_billing_settings_created_at"),
        "isp_billing_settings",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_billing_settings_created_by"),
        "isp_billing_settings",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_billing_settings_deleted_at"),
        "isp_billing_settings",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_billing_settings_is_deleted"),
        "isp_billing_settings",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_billing_settings_updated_by"),
        "isp_billing_settings",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_customer_billing",
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("plan_name", sa.String(length=100), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        sa.Column(
            "price_includes_gst",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("billing_cycle", sa.String(length=16), nullable=False),
        sa.Column("anchor_day", sa.SmallInteger(), nullable=False),
        sa.Column("next_invoice_date", sa.Date(), nullable=False),
        sa.Column(
            "gst_applicable",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("place_of_supply_state_code", sa.String(length=2), nullable=True),
        sa.Column("buyer_gstin", sa.String(length=15), nullable=True),
        sa.Column(
            "active", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_customer_billing_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_customer_billing_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_customer_billing")),
        sa.UniqueConstraint(
            "customer_organization_id",
            name=op.f("uq_isp_customer_billing_customer_organization_id"),
        ),
    )
    op.create_index(
        op.f("ix_isp_customer_billing_created_at"),
        "isp_customer_billing",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_billing_created_by"),
        "isp_customer_billing",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_billing_deleted_at"),
        "isp_customer_billing",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_billing_is_deleted"),
        "isp_customer_billing",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_isp_customer_billing_isp",
        "isp_customer_billing",
        ["isp_organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_billing_updated_by"),
        "isp_customer_billing",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_customer_service_state",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=32), nullable=True),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.Column(
            "show_suspended_page",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("requested_by", sa.UUID(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("idempotency_key", sa.String(length=100), nullable=True),
        sa.Column(
            "idempotent_response",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "warnings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f(
                "fk_isp_customer_service_state_customer_organization_id_organizations"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f(
                "fk_isp_customer_service_state_isp_organization_id_organizations"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name=op.f("fk_isp_customer_service_state_requested_by_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_customer_service_state")),
        sa.UniqueConstraint(
            "customer_organization_id",
            name=op.f("uq_isp_customer_service_state_customer_organization_id"),
        ),
    )
    op.create_index(
        op.f("ix_isp_customer_service_state_created_at"),
        "isp_customer_service_state",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_service_state_created_by"),
        "isp_customer_service_state",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_service_state_deleted_at"),
        "isp_customer_service_state",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_service_state_is_deleted"),
        "isp_customer_service_state",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_isp_customer_service_state_isp",
        "isp_customer_service_state",
        ["isp_organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_isp_customer_service_state_state",
        "isp_customer_service_state",
        ["state"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_customer_service_state_updated_by"),
        "isp_customer_service_state",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_invoice_sequences",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("series", sa.String(length=16), nullable=False),
        sa.Column("fy", sa.String(length=5), nullable=False),
        sa.Column("next_value", sa.Integer(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_invoice_sequences_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_invoice_sequences")),
    )
    op.create_index(
        op.f("ix_isp_invoice_sequences_created_at"),
        "isp_invoice_sequences",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_sequences_created_by"),
        "isp_invoice_sequences",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_sequences_deleted_at"),
        "isp_invoice_sequences",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_sequences_is_deleted"),
        "isp_invoice_sequences",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_sequences_updated_by"),
        "isp_invoice_sequences",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "uq_isp_invoice_sequences_key",
        "isp_invoice_sequences",
        ["isp_organization_id", "series", "fy"],
        unique=True,
    )
    op.create_table(
        "isp_payments",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=True),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        sa.Column("unallocated_paise", sa.BigInteger(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("reference", sa.String(length=100), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_by", sa.UUID(), nullable=True),
        sa.Column("receipt_fy", sa.String(length=5), nullable=False),
        sa.Column("receipt_seq", sa.Integer(), nullable=False),
        sa.Column("receipt_number", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("voided_reason", sa.String(length=255), nullable=True),
        sa.Column("gateway_payment_id", sa.String(length=64), nullable=True),
        sa.Column("gateway_link_id", sa.String(length=64), nullable=True),
        sa.Column("idempotency_key", sa.String(length=100), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_payments_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_payments_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["recorded_by"],
            ["users.id"],
            name=op.f("fk_isp_payments_recorded_by_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_payments")),
    )
    op.create_index(
        op.f("ix_isp_payments_created_at"), "isp_payments", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_payments_created_by"), "isp_payments", ["created_by"], unique=False
    )
    op.create_index(
        op.f("ix_isp_payments_deleted_at"), "isp_payments", ["deleted_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_payments_is_deleted"), "isp_payments", ["is_deleted"], unique=False
    )
    op.create_index(
        "ix_isp_payments_isp_customer",
        "isp_payments",
        ["isp_organization_id", "customer_organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_payments_updated_by"), "isp_payments", ["updated_by"], unique=False
    )
    op.create_index(
        "uq_isp_payments_gateway_payment",
        "isp_payments",
        ["isp_organization_id", "gateway_payment_id"],
        unique=True,
        postgresql_where=sa.text("gateway_payment_id IS NOT NULL"),
    )
    op.create_index(
        "uq_isp_payments_idempotency",
        "isp_payments",
        ["isp_organization_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "uq_isp_payments_receipt",
        "isp_payments",
        ["isp_organization_id", "receipt_fy", "receipt_seq"],
        unique=True,
    )
    op.create_table(
        "isp_zones",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("city", sa.String(length=100), nullable=True),
        sa.Column("state_code", sa.String(length=2), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_zones_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_zones")),
    )
    op.create_index(
        op.f("ix_isp_zones_created_at"), "isp_zones", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_zones_created_by"), "isp_zones", ["created_by"], unique=False
    )
    op.create_index(
        op.f("ix_isp_zones_deleted_at"), "isp_zones", ["deleted_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_zones_is_deleted"), "isp_zones", ["is_deleted"], unique=False
    )
    op.create_index(
        op.f("ix_isp_zones_updated_by"), "isp_zones", ["updated_by"], unique=False
    )
    op.create_index(
        "uq_isp_zones_isp_name",
        "isp_zones",
        ["isp_organization_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_invoices",
        sa.Column(
            "display_id", sa.BigInteger(), sa.Identity(always=False), nullable=False
        ),
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "doc_type", sa.String(length=12), server_default="invoice", nullable=False
        ),
        sa.Column(
            "bill_to_kind",
            sa.String(length=12),
            server_default="customer",
            nullable=False,
        ),
        sa.Column("customer_organization_id", sa.UUID(), nullable=True),
        sa.Column("fy", sa.String(length=5), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("number", sa.String(length=16), nullable=False),
        sa.Column("invoice_kind", sa.String(length=12), nullable=False),
        sa.Column("source_key", sa.String(length=120), nullable=True),
        sa.Column("issue_date", sa.Date(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=True),
        sa.Column("period_end", sa.Date(), nullable=True),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("bill_to_name", sa.String(length=255), nullable=False),
        sa.Column("bill_to_gstin", sa.String(length=15), nullable=True),
        sa.Column("bill_to_address", sa.Text(), nullable=True),
        sa.Column("place_of_supply_state_code", sa.String(length=2), nullable=True),
        sa.Column("seller_state_code", sa.String(length=2), nullable=True),
        sa.Column("zone_id", sa.UUID(), nullable=True),
        sa.Column("po_number", sa.String(length=40), nullable=True),
        sa.Column("gst_applied", sa.Boolean(), nullable=False),
        sa.Column("taxable_paise", sa.BigInteger(), nullable=False),
        sa.Column("cgst_paise", sa.BigInteger(), nullable=False),
        sa.Column("sgst_paise", sa.BigInteger(), nullable=False),
        sa.Column("igst_paise", sa.BigInteger(), nullable=False),
        sa.Column("total_paise", sa.BigInteger(), nullable=False),
        sa.Column("paid_paise", sa.BigInteger(), nullable=False),
        sa.Column("credit_noted_paise", sa.BigInteger(), nullable=False),
        sa.Column("credit_note_for_invoice_id", sa.UUID(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("cancelled_reason", sa.String(length=255), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "bill_to_kind = 'customer' AND customer_organization_id IS NOT NULL",
            name=op.f("ck_isp_invoices_bill_to"),
        ),
        sa.ForeignKeyConstraint(
            ["credit_note_for_invoice_id"],
            ["isp_invoices.id"],
            name=op.f("fk_isp_invoices_credit_note_for_invoice_id_isp_invoices"),
        ),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_invoices_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_invoices_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["zone_id"],
            ["isp_zones.id"],
            name=op.f("fk_isp_invoices_zone_id_isp_zones"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_invoices")),
        sa.UniqueConstraint("display_id", name=op.f("uq_isp_invoices_display_id")),
    )
    op.create_index(
        op.f("ix_isp_invoices_created_at"), "isp_invoices", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_invoices_created_by"), "isp_invoices", ["created_by"], unique=False
    )
    op.create_index(
        op.f("ix_isp_invoices_deleted_at"), "isp_invoices", ["deleted_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_invoices_is_deleted"), "isp_invoices", ["is_deleted"], unique=False
    )
    op.create_index(
        "ix_isp_invoices_isp_customer",
        "isp_invoices",
        ["isp_organization_id", "customer_organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_isp_invoices_issue_date",
        "isp_invoices",
        ["isp_organization_id", "issue_date"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoices_updated_by"), "isp_invoices", ["updated_by"], unique=False
    )
    op.create_index(
        "uq_isp_invoices_series",
        "isp_invoices",
        ["isp_organization_id", "doc_type", "fy", "seq"],
        unique=True,
    )
    op.create_index(
        "uq_isp_invoices_source_key",
        "isp_invoices",
        ["isp_organization_id", "source_key"],
        unique=True,
        postgresql_where=sa.text("source_key IS NOT NULL"),
    )
    op.create_table(
        "isp_invoice_lines",
        sa.Column("invoice_id", sa.UUID(), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column("sac_code", sa.String(length=8), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("unit_amount_paise", sa.BigInteger(), nullable=False),
        sa.Column("price_includes_gst", sa.Boolean(), nullable=False),
        sa.Column("taxable_paise", sa.BigInteger(), nullable=False),
        sa.Column("cgst_paise", sa.BigInteger(), nullable=False),
        sa.Column("sgst_paise", sa.BigInteger(), nullable=False),
        sa.Column("igst_paise", sa.BigInteger(), nullable=False),
        sa.Column("total_paise", sa.BigInteger(), nullable=False),
        sa.Column("period_from", sa.Date(), nullable=True),
        sa.Column("period_to", sa.Date(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["isp_invoices.id"],
            name=op.f("fk_isp_invoice_lines_invoice_id_isp_invoices"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_invoice_lines")),
    )
    op.create_index(
        op.f("ix_isp_invoice_lines_created_at"),
        "isp_invoice_lines",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_lines_created_by"),
        "isp_invoice_lines",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_lines_deleted_at"),
        "isp_invoice_lines",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        "ix_isp_invoice_lines_invoice",
        "isp_invoice_lines",
        ["invoice_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_lines_is_deleted"),
        "isp_invoice_lines",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_lines_updated_by"),
        "isp_invoice_lines",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_invoice_reminders",
        sa.Column("invoice_id", sa.UUID(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("sent_by", sa.UUID(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=12), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["isp_invoices.id"],
            name=op.f("fk_isp_invoice_reminders_invoice_id_isp_invoices"),
        ),
        sa.ForeignKeyConstraint(
            ["sent_by"],
            ["users.id"],
            name=op.f("fk_isp_invoice_reminders_sent_by_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_invoice_reminders")),
    )
    op.create_index(
        op.f("ix_isp_invoice_reminders_created_at"),
        "isp_invoice_reminders",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_reminders_created_by"),
        "isp_invoice_reminders",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_reminders_deleted_at"),
        "isp_invoice_reminders",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        "ix_isp_invoice_reminders_invoice",
        "isp_invoice_reminders",
        ["invoice_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_reminders_is_deleted"),
        "isp_invoice_reminders",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_invoice_reminders_updated_by"),
        "isp_invoice_reminders",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_payment_allocations",
        sa.Column("payment_id", sa.UUID(), nullable=False),
        sa.Column("invoice_id", sa.UUID(), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "amount_paise > 0", name=op.f("ck_isp_payment_allocations_positive")
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["isp_invoices.id"],
            name=op.f("fk_isp_payment_allocations_invoice_id_isp_invoices"),
        ),
        sa.ForeignKeyConstraint(
            ["payment_id"],
            ["isp_payments.id"],
            name=op.f("fk_isp_payment_allocations_payment_id_isp_payments"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_payment_allocations")),
    )
    op.create_index(
        op.f("ix_isp_payment_allocations_created_at"),
        "isp_payment_allocations",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_payment_allocations_created_by"),
        "isp_payment_allocations",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_payment_allocations_deleted_at"),
        "isp_payment_allocations",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        "ix_isp_payment_allocations_invoice",
        "isp_payment_allocations",
        ["invoice_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_payment_allocations_is_deleted"),
        "isp_payment_allocations",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_isp_payment_allocations_payment",
        "isp_payment_allocations",
        ["payment_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_payment_allocations_updated_by"),
        "isp_payment_allocations",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_service_actions",
        sa.Column("state_id", sa.UUID(), nullable=False),
        sa.Column("transition", sa.String(length=10), nullable=False),
        sa.Column("router_id", sa.UUID(), nullable=True),
        sa.Column("location_id", sa.UUID(), nullable=True),
        sa.Column("nas_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=12), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("detail", sa.String(length=255), nullable=True),
        sa.Column(
            "prior_state",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name=op.f("fk_isp_service_actions_location_id_locations"),
        ),
        sa.ForeignKeyConstraint(
            ["nas_id"],
            ["radius_nas_clients.id"],
            name=op.f("fk_isp_service_actions_nas_id_radius_nas_clients"),
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name=op.f("fk_isp_service_actions_router_id_routers"),
        ),
        sa.ForeignKeyConstraint(
            ["state_id"],
            ["isp_customer_service_state.id"],
            name=op.f("fk_isp_service_actions_state_id_isp_customer_service_state"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_service_actions")),
    )
    op.create_index(
        op.f("ix_isp_service_actions_created_at"),
        "isp_service_actions",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_service_actions_created_by"),
        "isp_service_actions",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_service_actions_deleted_at"),
        "isp_service_actions",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_service_actions_is_deleted"),
        "isp_service_actions",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_isp_service_actions_state_id",
        "isp_service_actions",
        ["state_id"],
        unique=False,
    )
    op.create_index(
        "ix_isp_service_actions_status", "isp_service_actions", ["status"], unique=False
    )
    op.create_index(
        op.f("ix_isp_service_actions_updated_by"),
        "isp_service_actions",
        ["updated_by"],
        unique=False,
    )
    op.add_column(
        "isp_customer_profiles", sa.Column("zone_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_isp_customer_profiles_zone_id_isp_zones"),
        "isp_customer_profiles",
        "isp_zones",
        ["zone_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_isp_customer_profiles_zone_id_isp_zones",
        "isp_customer_profiles",
        type_="foreignkey",
    )
    op.drop_column("isp_customer_profiles", "zone_id")
    for table in (
        "isp_invoice_reminders",
        "isp_payment_allocations",
        "isp_payments",
        "isp_invoice_lines",
        "isp_invoices",
        "isp_invoice_sequences",
        "isp_zones",
        "isp_customer_billing",
        "isp_billing_settings",
        "isp_service_actions",
        "isp_customer_service_state",
    ):
        op.drop_table(table)

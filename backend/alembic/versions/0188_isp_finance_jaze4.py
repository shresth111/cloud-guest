"""JAZE-4: ISP finance and communications tables (ADDENDUM_05 J7, J9, J10,
J14, J15, J23, security deposits).

Additive only: twelve new ISP-owned tables. No pre-ISP table is touched.
``downgrade`` drops exactly these.

Revision ID: 0188_isp_finance_jaze4
Revises: 0187_isp_jaze3_compliance
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0188_isp_finance_jaze4"
down_revision = "0187_isp_jaze3_compliance"
branch_labels = None
depends_on = None

_TABLES = (
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
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def upgrade() -> None:
    op.create_table(
        "isp_invoice_templates",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("bank_name", sa.String(length=100), nullable=True),
        sa.Column("bank_account_name", sa.String(length=120), nullable=True),
        sa.Column("bank_account_number", sa.String(length=34), nullable=True),
        sa.Column("bank_ifsc", sa.String(length=11), nullable=True),
        sa.Column("bank_branch", sa.String(length=100), nullable=True),
        sa.Column("website", sa.String(length=200), nullable=True),
        sa.Column("care_phone", sa.String(length=20), nullable=True),
        sa.Column("care_email", sa.String(length=255), nullable=True),
        sa.Column("pan", sa.String(length=10), nullable=True),
        sa.Column("licence_number", sa.String(length=60), nullable=True),
        sa.Column("terms", sa.Text(), nullable=True),
        sa.Column(
            "show_bank_details", sa.Boolean(), server_default="true", nullable=False
        ),
        sa.Column(
            "show_zone_operator", sa.Boolean(), server_default="true", nullable=False
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
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_invoice_templates_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_invoice_templates")),
    )
    op.create_index(
        "uq_isp_invoice_templates_isp",
        "isp_invoice_templates",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_billing_products",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column(
            "sac_code", sa.String(length=8), server_default="998422", nullable=False
        ),
        sa.Column(
            "default_amount_paise", sa.BigInteger(), server_default="0", nullable=False
        ),
        sa.Column(
            "price_includes_gst", sa.Boolean(), server_default="false", nullable=False
        ),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('bandwidth','static_ip','installation','other')",
            name=op.f("ck_isp_billing_products_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_billing_products_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_billing_products")),
    )
    op.create_index(
        "uq_isp_billing_products_name",
        "isp_billing_products",
        ["isp_organization_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_package_billing",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("package_id", sa.UUID(), nullable=False),
        sa.Column("plan_kind", sa.String(length=10), nullable=False),
        sa.Column("chargeable_unit", sa.String(length=8), nullable=False),
        sa.Column("chargeable_count", sa.Integer(), nullable=False),
        sa.Column("invoice_description", sa.String(length=255), nullable=True),
        sa.Column("product_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "chargeable_unit IN ('days','months')",
            name=op.f("ck_isp_package_billing_unit"),
        ),
        sa.CheckConstraint(
            "plan_kind IN ('prepaid','postpaid')",
            name=op.f("ck_isp_package_billing_plan_kind"),
        ),
        sa.CheckConstraint(
            "chargeable_count BETWEEN 1 AND 366",
            name=op.f("ck_isp_package_billing_count"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_package_billing_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["package_id"],
            ["isp_packages.id"],
            name=op.f("fk_isp_package_billing_package_id_isp_packages"),
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["isp_billing_products.id"],
            name=op.f("fk_isp_package_billing_product_id_isp_billing_products"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_package_billing")),
    )
    op.create_index(
        "uq_isp_package_billing_package",
        "isp_package_billing",
        ["package_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_static_ip_leases",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("subscriber_id", sa.UUID(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("monthly_amount_paise", sa.BigInteger(), nullable=False),
        sa.Column(
            "price_includes_gst", sa.Boolean(), server_default="false", nullable=False
        ),
        sa.Column("active_since", sa.Date(), nullable=False),
        sa.Column("active_until", sa.Date(), nullable=True),
        sa.Column("billed_through", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("notes", sa.String(length=255), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN ('active','ended')", name=op.f("ck_isp_static_ip_leases_status")
        ),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_static_ip_leases_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_static_ip_leases_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["subscriber_id"],
            ["isp_subscribers.id"],
            name=op.f("fk_isp_static_ip_leases_subscriber_id_isp_subscribers"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_static_ip_leases")),
    )
    op.create_index(
        "ix_isp_static_ip_leases_subscriber",
        "isp_static_ip_leases",
        ["subscriber_id"],
        unique=False,
    )
    op.create_index(
        "uq_isp_static_ip_leases_active_ip",
        "isp_static_ip_leases",
        ["isp_organization_id", "ip_address"],
        unique=True,
        postgresql_where=sa.text("status = 'active' AND deleted_at IS NULL"),
    )
    op.create_table(
        "isp_security_deposits",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("subscriber_id", sa.UUID(), nullable=True),
        sa.Column("entry_kind", sa.String(length=8), nullable=False),
        sa.Column("item", sa.String(length=8), nullable=False),
        sa.Column("item_serial", sa.String(length=64), nullable=True),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("reference", sa.String(length=100), nullable=True),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "entry_kind IN ('collect','refund','forfeit')",
            name=op.f("ck_isp_security_deposits_kind"),
        ),
        sa.CheckConstraint(
            "amount_paise > 0", name=op.f("ck_isp_security_deposits_positive")
        ),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f(
                "fk_isp_security_deposits_customer_organization_id_organizations"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_security_deposits_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["subscriber_id"],
            ["isp_subscribers.id"],
            name=op.f("fk_isp_security_deposits_subscriber_id_isp_subscribers"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_security_deposits")),
    )
    op.create_index(
        "ix_isp_security_deposits_isp_customer",
        "isp_security_deposits",
        ["isp_organization_id", "customer_organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_isp_security_deposits_subscriber",
        "isp_security_deposits",
        ["subscriber_id"],
        unique=False,
    )
    op.create_table(
        "isp_billing_contacts",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("subject_kind", sa.String(length=10), nullable=False),
        sa.Column("subject_id", sa.UUID(), nullable=False),
        sa.Column("alternate_email", sa.String(length=255), nullable=True),
        sa.Column("alternate_name", sa.String(length=120), nullable=True),
        sa.Column(
            "exclude_from_reminders",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
        sa.Column(
            "whatsapp_opt_in", sa.Boolean(), server_default="false", nullable=False
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
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_billing_contacts_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_billing_contacts")),
    )
    op.create_index(
        "uq_isp_billing_contacts_subject",
        "isp_billing_contacts",
        ["isp_organization_id", "subject_kind", "subject_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_automation_settings",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "whatsapp_enabled", sa.Boolean(), server_default="false", nullable=False
        ),
        sa.Column("whatsapp_enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "whatsapp_templates",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("pre_expiry_days", sa.Integer(), server_default="2", nullable=False),
        sa.Column(
            "unpaid_reminder_after_days",
            sa.Integer(),
            server_default="1",
            nullable=False,
        ),
        sa.Column(
            "telegram_enabled", sa.Boolean(), server_default="false", nullable=False
        ),
        sa.Column("telegram_bot_token_encrypted", sa.Text(), nullable=True),
        sa.Column("telegram_bot_token_hint", sa.String(length=12), nullable=True),
        sa.Column("telegram_chat_id", sa.String(length=64), nullable=True),
        sa.Column(
            "telegram_debounce_minutes",
            sa.Integer(),
            server_default="3",
            nullable=False,
        ),
        sa.Column(
            "telegram_include_aps", sa.Boolean(), server_default="true", nullable=False
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
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_automation_settings_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_automation_settings")),
    )
    op.create_index(
        "uq_isp_automation_settings_isp",
        "isp_automation_settings",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_message_log",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("channel", sa.String(length=10), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("recipient_masked", sa.String(length=64), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=True),
        sa.Column("subscriber_id", sa.UUID(), nullable=True),
        sa.Column("invoice_id", sa.UUID(), nullable=True),
        sa.Column("payment_id", sa.UUID(), nullable=True),
        sa.Column("summary", sa.String(length=300), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("error", sa.String(length=300), nullable=True),
        sa.Column("provider_message_id", sa.String(length=128), nullable=True),
        sa.Column("notification_delivery_id", sa.UUID(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=160), nullable=True),
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
            name=op.f("fk_isp_message_log_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["isp_invoices.id"],
            name=op.f("fk_isp_message_log_invoice_id_isp_invoices"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_message_log_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["payment_id"],
            ["isp_payments.id"],
            name=op.f("fk_isp_message_log_payment_id_isp_payments"),
        ),
        sa.ForeignKeyConstraint(
            ["subscriber_id"],
            ["isp_subscribers.id"],
            name=op.f("fk_isp_message_log_subscriber_id_isp_subscribers"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_message_log")),
    )
    op.create_index(
        "ix_isp_message_log_isp_created",
        "isp_message_log",
        ["isp_organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_isp_message_log_dedupe",
        "isp_message_log",
        ["isp_organization_id", "dedupe_key"],
        unique=True,
        postgresql_where=sa.text("dedupe_key IS NOT NULL"),
    )
    op.create_table(
        "isp_alert_device_state",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("device_kind", sa.String(length=8), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("observed_status", sa.String(length=4), nullable=False),
        sa.Column("observed_since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notified_status", sa.String(length=4), nullable=True),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
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
            name=op.f("fk_isp_alert_device_state_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_alert_device_state")),
    )
    op.create_index(
        "uq_isp_alert_device_state_device",
        "isp_alert_device_state",
        ["isp_organization_id", "device_kind", "device_id"],
        unique=True,
    )
    op.create_table(
        "isp_pay_links",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("invoice_id", sa.UUID(), nullable=False),
        sa.Column("token", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("open_count", sa.Integer(), server_default="0", nullable=False),
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
            name=op.f("fk_isp_pay_links_invoice_id_isp_invoices"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_pay_links_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_pay_links")),
    )
    op.create_index(
        "ix_isp_pay_links_invoice", "isp_pay_links", ["invoice_id"], unique=False
    )
    op.create_index("uq_isp_pay_links_token", "isp_pay_links", ["token"], unique=True)
    op.create_table(
        "isp_zone_profiles",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("zone_id", sa.UUID(), nullable=False),
        sa.Column("contact_name", sa.String(length=120), nullable=True),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("phone", sa.String(length=20), nullable=True),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column("pincode", sa.String(length=6), nullable=True),
        sa.Column("gstin", sa.String(length=15), nullable=True),
        sa.Column("pan", sa.String(length=10), nullable=True),
        sa.Column("operator_name", sa.String(length=120), nullable=True),
        sa.Column("operator_phone", sa.String(length=20), nullable=True),
        sa.Column("revenue_share_bp", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "credit_limit_paise", sa.BigInteger(), server_default="0", nullable=False
        ),
        sa.Column(
            "min_balance_paise", sa.BigInteger(), server_default="0", nullable=False
        ),
        sa.Column("tds_rate_bp", sa.Integer(), server_default="200", nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "credit_limit_paise >= 0", name=op.f("ck_isp_zone_profiles_credit")
        ),
        sa.CheckConstraint(
            "revenue_share_bp BETWEEN 0 AND 10000",
            name=op.f("ck_isp_zone_profiles_share"),
        ),
        sa.CheckConstraint(
            "tds_rate_bp BETWEEN 0 AND 10000", name=op.f("ck_isp_zone_profiles_tds")
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_zone_profiles_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["zone_id"],
            ["isp_zones.id"],
            name=op.f("fk_isp_zone_profiles_zone_id_isp_zones"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_zone_profiles")),
    )
    op.create_index(
        "uq_isp_zone_profiles_zone",
        "isp_zone_profiles",
        ["zone_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_zone_ledger_entries",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("zone_id", sa.UUID(), nullable=False),
        sa.Column("entry_kind", sa.String(length=12), nullable=False),
        sa.Column("amount_paise", sa.BigInteger(), nullable=False),
        sa.Column("balance_after_paise", sa.BigInteger(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=True),
        sa.Column("reference", sa.String(length=100), nullable=True),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "entry_kind IN ('add','reduce','credit_limit')",
            name=op.f("ck_isp_zone_ledger_entries_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_zone_ledger_entries_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["zone_id"],
            ["isp_zones.id"],
            name=op.f("fk_isp_zone_ledger_entries_zone_id_isp_zones"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_zone_ledger_entries")),
    )
    op.create_index(
        "ix_isp_zone_ledger_zone_time",
        "isp_zone_ledger_entries",
        ["zone_id", "occurred_at"],
        unique=False,
    )

    for table in _TABLES:
        for col in _BASE_INDEXED:
            op.create_index(op.f(f"ix_{table}_{col}"), table, [col], unique=False)


def downgrade() -> None:
    op.drop_table("isp_zone_ledger_entries")
    op.drop_table("isp_zone_profiles")
    op.drop_table("isp_pay_links")
    op.drop_table("isp_alert_device_state")
    op.drop_table("isp_message_log")
    op.drop_table("isp_automation_settings")
    op.drop_table("isp_billing_contacts")
    op.drop_table("isp_security_deposits")
    op.drop_table("isp_static_ip_leases")
    op.drop_table("isp_package_billing")
    op.drop_table("isp_billing_products")
    op.drop_table("isp_invoice_templates")

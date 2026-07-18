"""Create subscription, billing, license, payment, invoice, branding, theme, and custom domain tables.

Revision ID: 0009_create_billing_and_branding_tables
Revises: 0008_add_router_fk_to_rbac_tables
Create Date: 2026-07-18
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0009_create_billing_and_branding_tables"
down_revision = "0008_add_router_fk_to_rbac_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- subscription_plans ---
    op.create_table(
        "subscription_plans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("price_monthly", sa.Numeric(precision=10, scale=2), nullable=False),
        sa.Column("price_yearly", sa.Numeric(precision=10, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, default="USD"),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.Column("trial_days", sa.Integer(), nullable=False, default=0),
        sa.Column("limits", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_subscription_plans_code", "subscription_plans", ["code"])

    # --- subscriptions ---
    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("billing_cycle", sa.String(length=20), nullable=False),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trial_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trial_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("auto_renew", sa.Boolean(), nullable=False, default=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False, default=False),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("grace_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"]),
    )
    op.create_index("ix_subscriptions_organization_id", "subscriptions", ["organization_id"])
    op.create_index("ix_subscriptions_status", "subscriptions", ["status"])
    op.create_index("ix_subscriptions_org_status", "subscriptions", ["organization_id", "status"])

    # --- plan_change_history ---
    op.create_table(
        "plan_change_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("old_plan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("new_plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("changed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
        sa.ForeignKeyConstraint(["old_plan_id"], ["subscription_plans.id"]),
        sa.ForeignKeyConstraint(["new_plan_id"], ["subscription_plans.id"]),
    )
    op.create_index("ix_plan_change_history_organization_id", "plan_change_history", ["organization_id"])

    # --- billing_profiles ---
    op.create_table(
        "billing_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("customer_id", sa.String(length=100), nullable=True, unique=True),
        sa.Column("payment_method_id", sa.String(length=100), nullable=True),
        sa.Column("card_brand", sa.String(length=50), nullable=True),
        sa.Column("card_last4", sa.String(length=4), nullable=True),
        sa.Column("billing_email", sa.String(length=255), nullable=True),
        sa.Column("billing_phone", sa.String(length=50), nullable=True),
        sa.Column("billing_address", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("tax_id", sa.String(length=100), nullable=True),
        sa.Column("tax_id_type", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_billing_profiles_organization_id", "billing_profiles", ["organization_id"])
    op.create_index("ix_billing_profiles_customer_id", "billing_profiles", ["customer_id"])

    # --- licenses ---
    op.create_table(
        "licenses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("license_key", sa.String(length=100), nullable=False, unique=True),
        sa.Column("status", sa.String(length=50), nullable=False, default="issued"),
        sa.Column("tier", sa.String(length=50), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deallocated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_licenses_organization_id", "licenses", ["organization_id"])
    op.create_index("ix_licenses_router_id", "licenses", ["router_id"])
    op.create_index("ix_licenses_license_key", "licenses", ["license_key"])

    # --- payments ---
    op.create_table(
        "payments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subscription_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("gateway", sa.String(length=50), nullable=False),
        sa.Column("gateway_payment_intent_id", sa.String(length=150), nullable=True, unique=True),
        sa.Column("gateway_charge_id", sa.String(length=150), nullable=True, unique=True),
        sa.Column("amount", sa.Numeric(precision=10, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, default="USD"),
        sa.Column("tax_amount", sa.Numeric(precision=10, scale=2), nullable=False, default=0.00),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("refund_amount", sa.Numeric(precision=10, scale=2), nullable=False, default=0.00),
        sa.Column("failure_reason", sa.String(length=255), nullable=True),
        sa.Column("card_brand", sa.String(length=50), nullable=True),
        sa.Column("card_last4", sa.String(length=4), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_payments_organization_id", "payments", ["organization_id"])
    op.create_index("ix_payments_subscription_id", "payments", ["subscription_id"])
    op.create_index("ix_payments_invoice_id", "payments", ["invoice_id"])
    op.create_index("ix_payments_gateway_payment_intent_id", "payments", ["gateway_payment_intent_id"])

    # --- coupons ---
    op.create_table(
        "coupons",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(length=50), nullable=False, unique=True),
        sa.Column("discount_type", sa.String(length=20), nullable=False),
        sa.Column("discount_value", sa.Numeric(precision=10, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, default="USD"),
        sa.Column("active", sa.Boolean(), nullable=False, default=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_redemptions", sa.Integer(), nullable=True),
        sa.Column("redemptions_count", sa.Integer(), nullable=False, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_coupons_code", "coupons", ["code"])

    # --- invoices ---
    op.create_table(
        "invoices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subscription_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("invoice_number", sa.String(length=50), nullable=False, unique=True),
        sa.Column("status", sa.String(length=50), nullable=False, default="draft"),
        sa.Column("issue_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("subtotal", sa.Numeric(precision=10, scale=2), nullable=False, default=0.00),
        sa.Column("tax_amount", sa.Numeric(precision=10, scale=2), nullable=False, default=0.00),
        sa.Column("tax_rate", sa.Numeric(precision=5, scale=4), nullable=False, default=0.1800),
        sa.Column("discount_amount", sa.Numeric(precision=10, scale=2), nullable=False, default=0.00),
        sa.Column("total", sa.Numeric(precision=10, scale=2), nullable=False, default=0.00),
        sa.Column("currency", sa.String(length=3), nullable=False, default="USD"),
        sa.Column("pdf_url", sa.String(length=255), nullable=True),
        sa.Column("invoice_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_invoices_organization_id", "invoices", ["organization_id"])
    op.create_index("ix_invoices_subscription_id", "invoices", ["subscription_id"])
    op.create_index("ix_invoices_invoice_number", "invoices", ["invoice_number"])

    # --- credit_notes ---
    op.create_table(
        "credit_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("amount", sa.Numeric(precision=10, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, default="USD"),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, default="applied"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
        sa.ForeignKeyConstraint(["invoice_id"], ["invoices.id"]),
    )
    op.create_index("ix_credit_notes_organization_id", "credit_notes", ["organization_id"])

    # --- branding ---
    op.create_table(
        "branding",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("company_name", sa.String(length=100), nullable=False),
        sa.Column("logo_url", sa.String(length=255), nullable=True),
        sa.Column("dark_logo_url", sa.String(length=255), nullable=True),
        sa.Column("light_logo_url", sa.String(length=255), nullable=True),
        sa.Column("favicon_url", sa.String(length=255), nullable=True),
        sa.Column("primary_color", sa.String(length=10), nullable=False, default="#4F46E5"),
        sa.Column("secondary_color", sa.String(length=10), nullable=False, default="#0F172A"),
        sa.Column("typography", sa.String(length=50), nullable=False, default="Inter"),
        sa.Column("theme", sa.String(length=20), nullable=False, default="light"),
        sa.Column("footer_text", sa.Text(), nullable=True),
        sa.Column("support_email", sa.String(length=255), nullable=True),
        sa.Column("support_phone", sa.String(length=50), nullable=True),
        sa.Column("privacy_url", sa.String(length=255), nullable=True),
        sa.Column("terms_url", sa.String(length=255), nullable=True),
        sa.Column("help_center_url", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_branding_organization_id", "branding", ["organization_id"])
    op.create_index("ix_branding_location_id", "branding", ["location_id"])

    # --- themes ---
    op.create_table(
        "themes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("branding_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("landing_page_theme", sa.String(length=100), nullable=False, default="modern"),
        sa.Column("bg_image_url", sa.String(length=255), nullable=True),
        sa.Column("ad_banner_url", sa.String(length=255), nullable=True),
        sa.Column("custom_css", sa.Text(), nullable=True),
        sa.Column("custom_js", sa.Text(), nullable=True),
        sa.Column("terms_text", sa.Text(), nullable=True),
        sa.Column("privacy_text", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
        sa.ForeignKeyConstraint(["branding_id"], ["branding.id"]),
    )
    op.create_index("ix_themes_branding_id", "themes", ["branding_id"])
    op.create_index("ix_themes_organization_id", "themes", ["organization_id"])

    # --- custom_domains ---
    op.create_table(
        "custom_domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain_name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("verification_token", sa.String(length=100), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False, default=False),
        sa.Column("dns_validation_status", sa.String(length=50), nullable=False, default="pending"),
        sa.Column("ssl_status", sa.String(length=50), nullable=False, default="pending"),
        sa.Column("ssl_configured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, default=1),
    )
    op.create_index("ix_custom_domains_organization_id", "custom_domains", ["organization_id"])
    op.create_index("ix_custom_domains_domain_name", "custom_domains", ["domain_name"])


def downgrade() -> None:
    op.drop_table("custom_domains")
    op.drop_table("themes")
    op.drop_table("branding")
    op.drop_table("credit_notes")
    op.drop_table("invoices")
    op.drop_table("coupons")
    op.drop_table("payments")
    op.drop_table("licenses")
    op.drop_table("billing_profiles")
    op.drop_table("plan_change_history")
    op.drop_table("subscriptions")
    op.drop_table("subscription_plans")

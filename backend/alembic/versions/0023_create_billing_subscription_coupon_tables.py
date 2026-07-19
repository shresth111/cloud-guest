"""Create Billing Subscription + Coupon tables (BE-013 Part 2: Subscription
+ Renewal + Coupon Engines).

Mirrors ``0022_create_billing_plan_license_usage_tables``'s conventions:
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Four new tables, in dependency order:

* ``coupons`` -- discount codes (global or organization-specific). FK to
  ``organizations`` (``CASCADE``, nullable -- NULL = global coupon).
* ``coupon_plans`` -- the ``(coupon_id, plan_id)`` join table (unique
  together) backing ``Coupon.applicable_plan_ids`` -- a real join table,
  not a JSONB list, for referential integrity (see
  ``app.domains.billing.models.Coupon``'s own docstring). FK to
  ``coupons``/``plans`` (both ``CASCADE``).
* ``subscriptions`` -- one row per organization, ever (``organization_id``
  unique, mirrors ``licenses.organization_id``). FK to ``organizations``
  (``CASCADE``), ``licenses``/``plans`` (both ``RESTRICT``), ``coupons``
  (``SET NULL`` -- a subscription survives its referenced coupon being
  removed; the FK exists only after ``coupons`` above so this table must be
  created after it).
* ``coupon_usages`` -- one row per coupon redemption. FK to ``coupons``
  (``CASCADE``), ``organizations`` (``CASCADE``), ``subscriptions``
  (``SET NULL``, nullable) -- created last since it depends on
  ``subscriptions`` existing.

No RBAC follow-up migration is needed -- this part reuses RBAC's
already-seeded ``billing.*``/``subscriptions.*`` permission keys (seeded
since BE-004); the only RBAC edit this part makes is additive
``AuditAction`` values in ``app.domains.rbac.enums`` (no schema change).

Revision ID: 0023_create_billing_subscription_coupon_tables
Revises: 0022_create_billing_plan_license_usage_tables
Create Date: 2026-07-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0023_create_billing_subscription_coupon_tables"
down_revision = "0022_create_billing_plan_license_usage_tables"
branch_labels = None
depends_on = None


def _base_model_columns() -> list[sa.Column]:
    """Columns provided by ``app.database.base.BaseModel`` for every table."""
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def upgrade() -> None:
    # -- coupons ------------------------------------------------------------------
    op.create_table(
        "coupons",
        *_base_model_columns(),
        sa.Column("code", sa.String(50), nullable=False),
        sa.Column("discount_type", sa.String(20), nullable=False),
        sa.Column("discount_value", sa.Numeric(12, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("max_uses", sa.Integer(), nullable=True),
        sa.Column("current_uses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_coupons_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("code", name="uq_coupons_code"),
    )
    _create_base_model_indexes("coupons")
    op.create_index("ix_coupons_code", "coupons", ["code"])
    op.create_index("ix_coupons_organization_id", "coupons", ["organization_id"])
    op.create_index("ix_coupons_is_active", "coupons", ["is_active"])
    op.create_index("ix_coupons_valid_until", "coupons", ["valid_until"])

    # -- coupon_plans ---------------------------------------------------------------
    op.create_table(
        "coupon_plans",
        *_base_model_columns(),
        sa.Column("coupon_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["coupon_id"],
            ["coupons.id"],
            name="fk_coupon_plans_coupon_id_coupons",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["plans.id"],
            name="fk_coupon_plans_plan_id_plans",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("coupon_id", "plan_id", name="uq_coupon_plans_coupon_plan"),
    )
    _create_base_model_indexes("coupon_plans")
    op.create_index("ix_coupon_plans_coupon_id", "coupon_plans", ["coupon_id"])
    op.create_index("ix_coupon_plans_plan_id", "coupon_plans", ["plan_id"])

    # -- subscriptions ----------------------------------------------------------------
    op.create_table(
        "subscriptions",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("license_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("billing_cycle", sa.String(20), nullable=False),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trial_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("auto_renew", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "cancel_at_period_end",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_coupon_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("past_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_renewal_reminder_sent_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "last_expiry_reminder_sent_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_subscriptions_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["license_id"],
            ["licenses.id"],
            name="fk_subscriptions_license_id_licenses",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["plans.id"],
            name="fk_subscriptions_plan_id_plans",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["applied_coupon_id"],
            ["coupons.id"],
            name="fk_subscriptions_applied_coupon_id_coupons",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("organization_id", name="uq_subscriptions_organization_id"),
    )
    _create_base_model_indexes("subscriptions")
    op.create_index(
        "ix_subscriptions_organization_id",
        "subscriptions",
        ["organization_id"],
        unique=True,
    )
    op.create_index("ix_subscriptions_license_id", "subscriptions", ["license_id"])
    op.create_index("ix_subscriptions_plan_id", "subscriptions", ["plan_id"])
    op.create_index("ix_subscriptions_status", "subscriptions", ["status"])
    op.create_index(
        "ix_subscriptions_current_period_end", "subscriptions", ["current_period_end"]
    )
    op.create_index(
        "ix_subscriptions_applied_coupon_id", "subscriptions", ["applied_coupon_id"]
    )

    # -- coupon_usages ----------------------------------------------------------------
    op.create_table(
        "coupon_usages",
        *_base_model_columns(),
        sa.Column("coupon_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subscription_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("discount_amount_applied", sa.Numeric(12, 2), nullable=False),
        sa.ForeignKeyConstraint(
            ["coupon_id"],
            ["coupons.id"],
            name="fk_coupon_usages_coupon_id_coupons",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_coupon_usages_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["subscription_id"],
            ["subscriptions.id"],
            name="fk_coupon_usages_subscription_id_subscriptions",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("coupon_usages")
    op.create_index("ix_coupon_usages_coupon_id", "coupon_usages", ["coupon_id"])
    op.create_index(
        "ix_coupon_usages_organization_id", "coupon_usages", ["organization_id"]
    )
    op.create_index(
        "ix_coupon_usages_subscription_id", "coupon_usages", ["subscription_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_coupon_usages_subscription_id", table_name="coupon_usages")
    op.drop_index("ix_coupon_usages_organization_id", table_name="coupon_usages")
    op.drop_index("ix_coupon_usages_coupon_id", table_name="coupon_usages")
    _drop_base_model_indexes("coupon_usages")
    op.drop_table("coupon_usages")

    op.drop_index("ix_subscriptions_applied_coupon_id", table_name="subscriptions")
    op.drop_index("ix_subscriptions_current_period_end", table_name="subscriptions")
    op.drop_index("ix_subscriptions_status", table_name="subscriptions")
    op.drop_index("ix_subscriptions_plan_id", table_name="subscriptions")
    op.drop_index("ix_subscriptions_license_id", table_name="subscriptions")
    op.drop_index("ix_subscriptions_organization_id", table_name="subscriptions")
    _drop_base_model_indexes("subscriptions")
    op.drop_table("subscriptions")

    op.drop_index("ix_coupon_plans_plan_id", table_name="coupon_plans")
    op.drop_index("ix_coupon_plans_coupon_id", table_name="coupon_plans")
    _drop_base_model_indexes("coupon_plans")
    op.drop_table("coupon_plans")

    op.drop_index("ix_coupons_valid_until", table_name="coupons")
    op.drop_index("ix_coupons_is_active", table_name="coupons")
    op.drop_index("ix_coupons_organization_id", table_name="coupons")
    op.drop_index("ix_coupons_code", table_name="coupons")
    _drop_base_model_indexes("coupons")
    op.drop_table("coupons")

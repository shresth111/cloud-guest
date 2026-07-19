"""Create Billing Payment + PaymentMethod tables (BE-013 Part 3: Payment
Service + real Stripe/Razorpay Integration + Webhooks).

Mirrors ``0022_create_billing_plan_license_usage_tables``/
``0023_create_billing_subscription_coupon_tables``'s conventions: the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Two new tables, in dependency order:

* ``payments`` -- one row per real (or honestly-failed) charge attempt; this
  table doubles as the entire "Payment History" query surface (see
  ``app.domains.billing.models.Payment``'s own docstring) -- no second,
  append-only history table. FK to ``organizations`` (``CASCADE``),
  ``subscriptions`` (``SET NULL``, nullable). ``idempotency_key`` is
  **unique, not nullable** -- the real, database-enforced backstop behind
  this module's "same idempotency key never double-charges" guarantee (see
  that model's own docstring for the full write-up of how the application
  layer composes with this constraint).
* ``payment_methods`` -- a tokenized reference to a payment instrument
  (never raw card data). FK to ``organizations`` (``CASCADE``). A
  ``UniqueConstraint`` on ``(organization_id, provider,
  provider_payment_method_id)`` prevents registering the exact same
  provider token twice for the same organization.

No RBAC schema change -- this part reuses RBAC's already-seeded
``billing.*`` permission keys (seeded since BE-004); the only RBAC edit
this part makes is additive ``AuditAction`` values in
``app.domains.rbac.enums`` (no schema change). No ``alembic/env.py`` edit
was needed either -- that file already imports
``app.domains.billing.models`` as a whole module, so these two new classes
(defined in that same ``models.py``) are registered on ``Base.metadata``
automatically.

Revision ID: 0024_create_billing_payment_tables
Revises: 0023_create_billing_subscription_coupon_tables
Create Date: 2026-07-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0024_create_billing_payment_tables"
down_revision = "0023_create_billing_subscription_coupon_tables"
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
    # -- payments -------------------------------------------------------------------
    op.create_table(
        "payments",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subscription_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("provider_payment_id", sa.String(255), nullable=True),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column(
            "refunded_amount", sa.Numeric(12, 2), nullable=False, server_default="0"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_payments_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["subscription_id"],
            ["subscriptions.id"],
            name="fk_payments_subscription_id_subscriptions",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("idempotency_key", name="uq_payments_idempotency_key"),
    )
    _create_base_model_indexes("payments")
    op.create_index("ix_payments_organization_id", "payments", ["organization_id"])
    op.create_index("ix_payments_subscription_id", "payments", ["subscription_id"])
    op.create_index("ix_payments_status", "payments", ["status"])
    op.create_index("ix_payments_provider", "payments", ["provider"])
    op.create_index(
        "ix_payments_provider_payment_id", "payments", ["provider_payment_id"]
    )
    op.create_index(
        "ix_payments_idempotency_key", "payments", ["idempotency_key"], unique=True
    )

    # -- payment_methods --------------------------------------------------------------
    op.create_table(
        "payment_methods",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("provider_payment_method_id", sa.String(255), nullable=False),
        sa.Column("method_type", sa.String(20), nullable=False),
        sa.Column("last4", sa.String(4), nullable=True),
        sa.Column(
            "is_default", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_payment_methods_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "provider",
            "provider_payment_method_id",
            name="uq_payment_methods_org_provider_token",
        ),
    )
    _create_base_model_indexes("payment_methods")
    op.create_index(
        "ix_payment_methods_organization_id", "payment_methods", ["organization_id"]
    )
    op.create_index("ix_payment_methods_provider", "payment_methods", ["provider"])
    op.create_index("ix_payment_methods_is_default", "payment_methods", ["is_default"])
    op.create_index("ix_payment_methods_is_active", "payment_methods", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_payment_methods_is_active", table_name="payment_methods")
    op.drop_index("ix_payment_methods_is_default", table_name="payment_methods")
    op.drop_index("ix_payment_methods_provider", table_name="payment_methods")
    op.drop_index("ix_payment_methods_organization_id", table_name="payment_methods")
    _drop_base_model_indexes("payment_methods")
    op.drop_table("payment_methods")

    op.drop_index("ix_payments_idempotency_key", table_name="payments")
    op.drop_index("ix_payments_provider_payment_id", table_name="payments")
    op.drop_index("ix_payments_provider", table_name="payments")
    op.drop_index("ix_payments_status", table_name="payments")
    op.drop_index("ix_payments_subscription_id", table_name="payments")
    op.drop_index("ix_payments_organization_id", table_name="payments")
    _drop_base_model_indexes("payments")
    op.drop_table("payments")

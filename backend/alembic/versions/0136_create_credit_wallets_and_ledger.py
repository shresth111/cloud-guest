"""Prepaid credits: ``credit_wallets`` and the append-only ``credit_ledger_entries``.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §13.2 (BE-12a).

Additive only: two new tables, one trigger function, two triggers. No
backfill -- every organization starts with no wallet row, which reads as a
zero balance, and the wallet is created at 0 on its first write.

* ``credit_wallets``: one row per ``(organization_id, bucket)``. Amounts are
  BIGINT minor units (100 minor = 1 credit) with ``CHECK (>= 0)`` on both
  buckets, so an overdraft is a failed write, never a negative balance.
* ``credit_ledger_entries``: signed deltas, running balances, and an
  ``idempotency_key`` unique per ``(organization_id, bucket)``. Append-only:
  ``credit_ledger_entries_append_only()`` refuses every UPDATE, and every
  DELETE except the cascade of the owning organization being deleted (the
  organization row is already gone when the cascade reaches the ledger).

Numbered 0136 because BYO providers (branch ``feat/marketing-byo``) claims
``0135_create_org_marketing_providers``. **Until that merges this revises
0134; re-point ``down_revision`` at 0135 once it is on main** (CI asserts a
single head).

Revision ID: 0136_create_credit_wallets_and_ledger
Revises: 0134_create_guest_marketing_tables
Create Date: 2026-09-26
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0136_create_credit_wallets_and_ledger"
down_revision = "0134_create_guest_marketing_tables"
branch_labels = None
depends_on = None


WALLETS = "credit_wallets"
LEDGER = "credit_ledger_entries"

# Kept as module constants so tests/unit/test_marketing_credits_postgres.py
# installs exactly this SQL rather than a copy of it.
APPEND_ONLY_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION credit_ledger_entries_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- The only legitimate delete is ON DELETE CASCADE from organizations:
        -- by the time the cascade reaches this row the organization row is
        -- already gone. A delete while the organization still exists is a
        -- hand-issued DELETE, and the ledger is append-only.
        IF NOT EXISTS (
            SELECT 1 FROM organizations WHERE id = OLD.organization_id
        ) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'credit_ledger_entries is append-only (% refused)', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;
"""

APPEND_ONLY_TRIGGERS_SQL = (
    """
CREATE TRIGGER credit_ledger_entries_no_update
BEFORE UPDATE ON credit_ledger_entries
FOR EACH ROW EXECUTE FUNCTION credit_ledger_entries_append_only();
""",
    """
CREATE TRIGGER credit_ledger_entries_no_delete
BEFORE DELETE ON credit_ledger_entries
FOR EACH ROW EXECUTE FUNCTION credit_ledger_entries_append_only();
""",
)


# House convention: base-model helpers are duplicated into each migration so
# it stays a frozen snapshot (see 0122's note).
def _base_model_columns() -> list[sa.Column]:
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
    op.create_table(
        WALLETS,
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("bucket", sa.String(length=20), nullable=False),
        sa.Column(
            "available_minor", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "reserved_minor", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "low_balance_threshold_minor",
            sa.BigInteger(),
            nullable=False,
            server_default="10000",
        ),
        sa.Column("low_balance_notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "organization_id", "bucket", name="uq_credit_wallets_org_bucket"
        ),
        sa.CheckConstraint(
            "available_minor >= 0", name="ck_credit_wallets_available_nonneg"
        ),
        sa.CheckConstraint(
            "reserved_minor >= 0", name="ck_credit_wallets_reserved_nonneg"
        ),
        sa.CheckConstraint(
            "low_balance_threshold_minor >= 0",
            name="ck_credit_wallets_threshold_nonneg",
        ),
    )
    _create_base_model_indexes(WALLETS)

    op.create_table(
        LEDGER,
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("bucket", sa.String(length=20), nullable=False),
        sa.Column("entry_type", sa.String(length=16), nullable=False),
        sa.Column("delta_available_minor", sa.BigInteger(), nullable=False),
        sa.Column("delta_reserved_minor", sa.BigInteger(), nullable=False),
        sa.Column("balance_available_after_minor", sa.BigInteger(), nullable=False),
        sa.Column("balance_reserved_after_minor", sa.BigInteger(), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("recipient_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "is_test_send", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("unit_price_minor", sa.Integer(), nullable=True),
        sa.Column("units", sa.Integer(), nullable=True),
        sa.Column("reference", sa.String(length=100), nullable=True),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column(
            "invoice_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("invoices.id"),
            nullable=True,
        ),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "bucket",
            "idempotency_key",
            name="uq_credit_ledger_entries_idempotency",
        ),
        sa.CheckConstraint(
            "entry_type IN ('topup','reserve','release','debit','refund',"
            "'adjustment')",
            name="ck_credit_ledger_entries_entry_type_valid",
        ),
        sa.CheckConstraint(
            "balance_available_after_minor >= 0 "
            "AND balance_reserved_after_minor >= 0",
            name="ck_credit_ledger_entries_balances_nonneg",
        ),
    )
    op.create_index(
        "ix_credit_ledger_entries_org_bucket_created",
        LEDGER,
        ["organization_id", "bucket", sa.text("created_at DESC")],
    )
    op.create_index("ix_credit_ledger_entries_campaign_id", LEDGER, ["campaign_id"])
    op.create_index(
        "uq_credit_ledger_entries_recipient_debit",
        LEDGER,
        ["recipient_id"],
        unique=True,
        postgresql_where=sa.text("entry_type = 'debit'"),
    )
    _create_base_model_indexes(LEDGER)

    op.execute(APPEND_ONLY_FUNCTION_SQL)
    for statement in APPEND_ONLY_TRIGGERS_SQL:
        op.execute(statement)


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS credit_ledger_entries_no_delete ON {LEDGER}")
    op.execute(f"DROP TRIGGER IF EXISTS credit_ledger_entries_no_update ON {LEDGER}")
    op.execute("DROP FUNCTION IF EXISTS credit_ledger_entries_append_only()")
    _drop_base_model_indexes(LEDGER)
    op.drop_index("uq_credit_ledger_entries_recipient_debit", table_name=LEDGER)
    op.drop_index("ix_credit_ledger_entries_campaign_id", table_name=LEDGER)
    op.drop_index("ix_credit_ledger_entries_org_bucket_created", table_name=LEDGER)
    op.drop_table(LEDGER)
    _drop_base_model_indexes(WALLETS)
    op.drop_table(WALLETS)

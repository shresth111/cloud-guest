"""Create Voucher domain tables: voucher_batches, vouchers.

Mirrors ``0012_create_otp_tables``'s conventions: each table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is Module 010 Part 2's only migration -- two new tables:

* ``voucher_batches`` -- one row per admin-initiated "generate N vouchers"
  request and its approval lifecycle. ``organization_id`` is a real,
  **non-nullable** FK to ``organizations.id`` (a batch always belongs to a
  tenant, unlike OTP's nullable scope columns); ``location_id`` is a real,
  nullable FK to ``locations.id`` (a batch may be org-wide or
  location-specific).
* ``vouchers`` -- one row per generated/imported voucher code. ``code`` is
  a plain, **unique**, plaintext ``String`` column (not hashed -- see
  ``app.domains.voucher.models.Voucher``'s module docstring for the full
  reasoning) with a real database-level ``UNIQUE`` constraint.
  ``redeemed_identifier`` is a plain string, not a FK: no ``Guest`` table
  exists yet in this codebase (a later module in this same BE-010
  sequence), the identical posture ``otp_requests.identifier`` already
  established.

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): neither table is referenced by any RBAC scope column.

Revision ID: 0013_create_voucher_tables
Revises: 0012_create_otp_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0013_create_voucher_tables"
down_revision = "0012_create_otp_tables"
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
    op.create_table(
        "voucher_batches",
        *_base_model_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("code_length", sa.Integer(), nullable=False),
        sa.Column("code_prefix", sa.String(20), nullable=True),
        sa.Column("validity_minutes", sa.Integer(), nullable=False),
        sa.Column("batch_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "max_uses_per_voucher", sa.Integer(), nullable=False, server_default="1"
        ),
        sa.Column("data_limit_mb", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_voucher_batches_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_voucher_batches_location_id_locations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("voucher_batches")
    op.create_index(
        "ix_voucher_batches_organization_id", "voucher_batches", ["organization_id"]
    )
    op.create_index(
        "ix_voucher_batches_location_id", "voucher_batches", ["location_id"]
    )
    op.create_index("ix_voucher_batches_status", "voucher_batches", ["status"])
    op.create_index(
        "ix_voucher_batches_batch_expires_at",
        "voucher_batches",
        ["batch_expires_at"],
    )

    op.create_table(
        "vouchers",
        *_base_model_columns(),
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="unused"),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("redeemed_identifier", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["voucher_batches.id"],
            name="fk_vouchers_batch_id_voucher_batches",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("code", name="uq_vouchers_code"),
    )
    _create_base_model_indexes("vouchers")
    op.create_index("ix_vouchers_batch_id", "vouchers", ["batch_id"])
    op.create_index("ix_vouchers_code", "vouchers", ["code"], unique=True)
    op.create_index("ix_vouchers_status", "vouchers", ["status"])


def downgrade() -> None:
    op.drop_index("ix_vouchers_status", table_name="vouchers")
    op.drop_index("ix_vouchers_code", table_name="vouchers")
    op.drop_index("ix_vouchers_batch_id", table_name="vouchers")
    _drop_base_model_indexes("vouchers")
    op.drop_table("vouchers")

    op.drop_index("ix_voucher_batches_batch_expires_at", table_name="voucher_batches")
    op.drop_index("ix_voucher_batches_status", table_name="voucher_batches")
    op.drop_index("ix_voucher_batches_location_id", table_name="voucher_batches")
    op.drop_index("ix_voucher_batches_organization_id", table_name="voucher_batches")
    _drop_base_model_indexes("voucher_batches")
    op.drop_table("voucher_batches")

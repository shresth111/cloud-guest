"""Create OTP domain table: otp_requests.

Mirrors ``0011_create_wireguard_tables``'s conventions: the table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is Module 010 Part 1's only migration -- one new table:

* ``otp_requests`` -- one row per generated OTP code. ``identifier`` is a
  plain string column (phone number or email), not a FK: no ``Guest`` table
  exists yet in this codebase (a later module in this same BE-010
  sequence). ``organization_id``/``location_id`` are real, nullable FKs to
  the already-existing ``organizations``/``locations`` tables (no deferred-
  FK situation here, unlike the ``router_id`` history elsewhere in this
  codebase).

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): ``otp_requests`` is not referenced by any RBAC scope column.

Revision ID: 0012_create_otp_tables
Revises: 0011_create_wireguard_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0012_create_otp_tables"
down_revision = "0011_create_wireguard_tables"
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
        "otp_requests",
        *_base_model_columns(),
        sa.Column("identifier", sa.String(255), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("purpose", sa.String(30), nullable=False),
        sa.Column("code_hash", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column(
            "is_consumed", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_otp_requests_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_otp_requests_location_id_locations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("otp_requests")
    op.create_index("ix_otp_requests_identifier", "otp_requests", ["identifier"])
    op.create_index("ix_otp_requests_purpose", "otp_requests", ["purpose"])
    op.create_index(
        "ix_otp_requests_identifier_purpose",
        "otp_requests",
        ["identifier", "purpose"],
    )
    op.create_index("ix_otp_requests_expires_at", "otp_requests", ["expires_at"])
    op.create_index(
        "ix_otp_requests_organization_id", "otp_requests", ["organization_id"]
    )
    op.create_index("ix_otp_requests_location_id", "otp_requests", ["location_id"])


def downgrade() -> None:
    op.drop_index("ix_otp_requests_location_id", table_name="otp_requests")
    op.drop_index("ix_otp_requests_organization_id", table_name="otp_requests")
    op.drop_index("ix_otp_requests_expires_at", table_name="otp_requests")
    op.drop_index("ix_otp_requests_identifier_purpose", table_name="otp_requests")
    op.drop_index("ix_otp_requests_purpose", table_name="otp_requests")
    op.drop_index("ix_otp_requests_identifier", table_name="otp_requests")
    _drop_base_model_indexes("otp_requests")
    op.drop_table("otp_requests")

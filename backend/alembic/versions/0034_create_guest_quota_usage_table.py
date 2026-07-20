"""Phase 1 BhaiFi-parity: ``guest_quota_usages`` (Fair Usage Policy quota
tracking).

New table, additive only -- no existing table is touched. One row per
``(guest_id, period_type)`` (daily/weekly/monthly), holding the cumulative
``bytes_used``/``minutes_used`` a guest has consumed within that
recurring period, plus the row's own current ``period_start`` boundary and
``last_accrued_at`` bookmark for time accrual. See
``app.domains.guest.models.GuestQuotaUsage``'s own docstring for the full
design write-up, and ``app.domains.guest.service``'s "FUP quota tracking"
module docstring section for how a row is read, bumped, and rolled over.

No RBAC schema change -- this table has no dedicated admin CRUD endpoints
of its own in this phase (it is read/written entirely by
``GuestService``'s own login-time enforcement, RADIUS accounting bump, and
the two new Celery Beat sweeps), so no new ``PermissionModule``/
``AuditAction`` seeding is needed.

Revision ID: 0034_create_guest_quota_usage_table
Revises: 0033_create_queue_management_tables
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0034_create_guest_quota_usage_table"
down_revision = "0033_create_queue_management_tables"
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
        "guest_quota_usages",
        *_base_model_columns(),
        sa.Column("guest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("period_type", sa.String(20), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bytes_used", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("minutes_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_accrued_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["guest_id"],
            ["guests.id"],
            name="fk_guest_quota_usages_guest_id_guests",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_guest_quota_usages_organization_id_organizations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("guest_quota_usages")
    op.create_index(
        "ix_guest_quota_usages_guest_id", "guest_quota_usages", ["guest_id"]
    )
    op.create_index(
        "ix_guest_quota_usages_organization_id",
        "guest_quota_usages",
        ["organization_id"],
    )
    op.create_index(
        "uq_guest_quota_usages_guest_id_period_type",
        "guest_quota_usages",
        ["guest_id", "period_type"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_guest_quota_usages_guest_id_period_type",
        table_name="guest_quota_usages",
    )
    op.drop_index(
        "ix_guest_quota_usages_organization_id", table_name="guest_quota_usages"
    )
    op.drop_index("ix_guest_quota_usages_guest_id", table_name="guest_quota_usages")
    _drop_base_model_indexes("guest_quota_usages")
    op.drop_table("guest_quota_usages")

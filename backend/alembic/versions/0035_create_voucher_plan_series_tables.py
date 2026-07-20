"""Phase 1 BhaiFi-parity: ``voucher_plans``, ``voucher_series``, plus
additive ``plan_id``/``series_id`` columns on ``voucher_batches`` and
``plan_id`` on ``vouchers``.

New tables (additive only -- no existing table's own columns are dropped or
retyped):

* ``voucher_plans`` -- a reusable, named "voucher product" definition (the
  speed a voucher grants once redeemed, plus default validity/data-cap/
  use-count). ``organization_id`` is nullable (a platform-wide template).
* ``voucher_series`` -- a named, ongoing campaign generated under exactly
  one ``voucher_plans`` row. ``organization_id`` is required (never
  platform-wide).

``voucher_batches.plan_id``/``series_id`` and ``vouchers.plan_id`` are all
nullable, ``ON DELETE SET NULL`` -- every batch/voucher created before this
migration (and any created afterward with no plan/series in mind) simply
has these as ``NULL``, exactly today's behavior. See
``app.domains.voucher.models``'s own docstrings for the full design
write-up.

No RBAC schema change -- ``VoucherPlan``/``VoucherSeries`` reuse the
already-seeded ``voucher.create``/``voucher.read`` permission keys (this
phase adds no new ``PermissionModule``/action), only two additive
``AuditAction`` enum values (``VOUCHER_PLAN_CREATED``/
``VOUCHER_SERIES_CREATED``, seeded at application/CLI startup like every
other domain's audit actions, never by a migration).

Revision ID: 0035_create_voucher_plan_series_tables
Revises: 0034_create_guest_quota_usage_table
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0035_create_voucher_plan_series_tables"
down_revision = "0034_create_guest_quota_usage_table"
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
    # -- voucher_plans -----------------------------------------------------------
    op.create_table(
        "voucher_plans",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "queue_profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("queue_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("default_validity_minutes", sa.Integer(), nullable=False),
        sa.Column("default_data_limit_mb", sa.Integer(), nullable=True),
        sa.Column(
            "default_max_uses_per_voucher",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("voucher_plans")
    op.create_index(
        "ix_voucher_plans_organization_id", "voucher_plans", ["organization_id"]
    )
    op.create_index(
        "ix_voucher_plans_queue_profile_id", "voucher_plans", ["queue_profile_id"]
    )
    op.create_index("ix_voucher_plans_is_active", "voucher_plans", ["is_active"])

    # -- voucher_series ------------------------------------------------------------
    op.create_table(
        "voucher_series",
        *_base_model_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("voucher_plans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("voucher_series")
    op.create_index(
        "ix_voucher_series_organization_id", "voucher_series", ["organization_id"]
    )
    op.create_index("ix_voucher_series_location_id", "voucher_series", ["location_id"])
    op.create_index("ix_voucher_series_plan_id", "voucher_series", ["plan_id"])
    op.create_index("ix_voucher_series_is_active", "voucher_series", ["is_active"])

    # -- voucher_batches: additive plan_id/series_id ---------------------------
    op.add_column(
        "voucher_batches",
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("voucher_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "voucher_batches",
        sa.Column(
            "series_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("voucher_series.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_voucher_batches_plan_id", "voucher_batches", ["plan_id"])
    op.create_index("ix_voucher_batches_series_id", "voucher_batches", ["series_id"])

    # -- vouchers: additive plan_id (denormalized from voucher_batches.plan_id) --
    op.add_column(
        "vouchers",
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("voucher_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_vouchers_plan_id", "vouchers", ["plan_id"])


def downgrade() -> None:
    op.drop_index("ix_vouchers_plan_id", table_name="vouchers")
    op.drop_column("vouchers", "plan_id")

    op.drop_index("ix_voucher_batches_series_id", table_name="voucher_batches")
    op.drop_index("ix_voucher_batches_plan_id", table_name="voucher_batches")
    op.drop_column("voucher_batches", "series_id")
    op.drop_column("voucher_batches", "plan_id")

    op.drop_index("ix_voucher_series_is_active", table_name="voucher_series")
    op.drop_index("ix_voucher_series_plan_id", table_name="voucher_series")
    op.drop_index("ix_voucher_series_location_id", table_name="voucher_series")
    op.drop_index("ix_voucher_series_organization_id", table_name="voucher_series")
    _drop_base_model_indexes("voucher_series")
    op.drop_table("voucher_series")

    op.drop_index("ix_voucher_plans_is_active", table_name="voucher_plans")
    op.drop_index("ix_voucher_plans_queue_profile_id", table_name="voucher_plans")
    op.drop_index("ix_voucher_plans_organization_id", table_name="voucher_plans")
    _drop_base_model_indexes("voucher_plans")
    op.drop_table("voucher_plans")

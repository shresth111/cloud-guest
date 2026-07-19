"""Create Billing domain tables (BE-013 Part 1: Plan + License + Usage
Core).

Mirrors ``0021_create_report_tables``'s conventions: the ``BaseModel``
column set (id, created_at, updated_at, soft-delete, audit, version) plus
its own base-model indexes, using the same ``_base_model_columns``/
``_create_base_model_indexes`` helpers (duplicated here, not imported --
Alembic migrations are meant to be self-contained snapshots rather than
depending on other migration modules).

Five new tables, in dependency order:

* ``plans`` -- the pricing/entitlement catalog.
* ``plan_features`` -- one entitlement/limit row per ``(plan_id,
  feature_key)`` (unique constraint), FK to ``plans`` (``CASCADE``).
* ``licenses`` -- one row per organization (``organization_id`` unique,
  ``CASCADE`` FK to ``organizations``), FK to ``plans`` (``RESTRICT`` --
  a plan referenced by an active license cannot be hard-deleted; this
  domain never hard-deletes plans anyway, only deactivates them).
* ``license_change_logs`` -- full upgrade/downgrade/assign audit history,
  FK to ``licenses`` (``CASCADE``) and ``plans`` (``from_plan_id`` ``SET
  NULL``, ``to_plan_id`` ``RESTRICT``).
* ``usage_metrics`` -- real, composed usage snapshots, FK to
  ``organizations`` (``CASCADE``).

No RBAC FK follow-up migration is needed -- this domain reuses RBAC's
already-seeded ``billing.*``/``subscriptions.*`` permission keys (seeded
since BE-004, see ``app.domains.rbac.seed``); the only RBAC edit this part
makes is additive ``AuditAction`` values in ``app.domains.rbac.enums``
(no schema change, an existing table's ``action`` column already accepts
any string).

Revision ID: 0022_create_billing_plan_license_usage_tables
Revises: 0021_create_report_tables
Create Date: 2026-07-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0022_create_billing_plan_license_usage_tables"
down_revision = "0021_create_report_tables"
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
    # -- plans ------------------------------------------------------------------
    op.create_table(
        "plans",
        *_base_model_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(150), nullable=False),
        sa.Column("plan_type", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("billing_cycle", sa.String(20), nullable=False),
        sa.Column("base_price", sa.Numeric(12, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="USD"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_public", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("slug", name="uq_plans_slug"),
    )
    _create_base_model_indexes("plans")
    op.create_index("ix_plans_slug", "plans", ["slug"])
    op.create_index("ix_plans_plan_type", "plans", ["plan_type"])
    op.create_index("ix_plans_is_active", "plans", ["is_active"])
    op.create_index("ix_plans_is_public", "plans", ["is_public"])
    op.create_index("ix_plans_sort_order", "plans", ["sort_order"])

    # -- plan_features ------------------------------------------------------------
    op.create_table(
        "plan_features",
        *_base_model_columns(),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("feature_key", sa.String(50), nullable=False),
        sa.Column("feature_type", sa.String(20), nullable=False),
        sa.Column("limit_value", sa.Numeric(18, 2), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=True),
        sa.Column("tier_value", sa.String(20), nullable=True),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["plans.id"],
            name="fk_plan_features_plan_id_plans",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "plan_id", "feature_key", name="uq_plan_features_plan_feature"
        ),
    )
    _create_base_model_indexes("plan_features")
    op.create_index("ix_plan_features_plan_id", "plan_features", ["plan_id"])
    op.create_index("ix_plan_features_feature_key", "plan_features", ["feature_key"])

    # -- licenses ------------------------------------------------------------------
    op.create_table(
        "licenses",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspended_reason", sa.Text(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_licenses_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["plans.id"],
            name="fk_licenses_plan_id_plans",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("organization_id", name="uq_licenses_organization_id"),
    )
    _create_base_model_indexes("licenses")
    op.create_index(
        "ix_licenses_organization_id", "licenses", ["organization_id"], unique=True
    )
    op.create_index("ix_licenses_plan_id", "licenses", ["plan_id"])
    op.create_index("ix_licenses_status", "licenses", ["status"])
    op.create_index("ix_licenses_expires_at", "licenses", ["expires_at"])

    # -- license_change_logs --------------------------------------------------------
    op.create_table(
        "license_change_logs",
        *_base_model_columns(),
        sa.Column("license_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("from_plan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("to_plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("change_type", sa.String(20), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["license_id"],
            ["licenses.id"],
            name="fk_license_change_logs_license_id_licenses",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["from_plan_id"],
            ["plans.id"],
            name="fk_license_change_logs_from_plan_id_plans",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["to_plan_id"],
            ["plans.id"],
            name="fk_license_change_logs_to_plan_id_plans",
            ondelete="RESTRICT",
        ),
    )
    _create_base_model_indexes("license_change_logs")
    op.create_index(
        "ix_license_change_logs_license_id", "license_change_logs", ["license_id"]
    )
    op.create_index(
        "ix_license_change_logs_changed_at", "license_change_logs", ["changed_at"]
    )

    # -- usage_metrics --------------------------------------------------------------
    op.create_table(
        "usage_metrics",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("metric_key", sa.String(30), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("value", sa.Numeric(18, 2), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_usage_metrics_organization_id_organizations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("usage_metrics")
    op.create_index(
        "ix_usage_metrics_organization_id", "usage_metrics", ["organization_id"]
    )
    op.create_index("ix_usage_metrics_metric_key", "usage_metrics", ["metric_key"])
    op.create_index("ix_usage_metrics_period_start", "usage_metrics", ["period_start"])
    op.create_index(
        "ix_usage_metrics_org_metric_period",
        "usage_metrics",
        ["organization_id", "metric_key", "period_start"],
    )


def downgrade() -> None:
    op.drop_index("ix_usage_metrics_org_metric_period", table_name="usage_metrics")
    op.drop_index("ix_usage_metrics_period_start", table_name="usage_metrics")
    op.drop_index("ix_usage_metrics_metric_key", table_name="usage_metrics")
    op.drop_index("ix_usage_metrics_organization_id", table_name="usage_metrics")
    _drop_base_model_indexes("usage_metrics")
    op.drop_table("usage_metrics")

    op.drop_index("ix_license_change_logs_changed_at", table_name="license_change_logs")
    op.drop_index("ix_license_change_logs_license_id", table_name="license_change_logs")
    _drop_base_model_indexes("license_change_logs")
    op.drop_table("license_change_logs")

    op.drop_index("ix_licenses_expires_at", table_name="licenses")
    op.drop_index("ix_licenses_status", table_name="licenses")
    op.drop_index("ix_licenses_plan_id", table_name="licenses")
    op.drop_index("ix_licenses_organization_id", table_name="licenses")
    _drop_base_model_indexes("licenses")
    op.drop_table("licenses")

    op.drop_index("ix_plan_features_feature_key", table_name="plan_features")
    op.drop_index("ix_plan_features_plan_id", table_name="plan_features")
    _drop_base_model_indexes("plan_features")
    op.drop_table("plan_features")

    op.drop_index("ix_plans_sort_order", table_name="plans")
    op.drop_index("ix_plans_is_public", table_name="plans")
    op.drop_index("ix_plans_is_active", table_name="plans")
    op.drop_index("ix_plans_plan_type", table_name="plans")
    op.drop_index("ix_plans_slug", table_name="plans")
    _drop_base_model_indexes("plans")
    op.drop_table("plans")

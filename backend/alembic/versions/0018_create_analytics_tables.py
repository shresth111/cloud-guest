"""Create Analytics tables (BE-012 Part 1: Analytics Core Infrastructure).

Mirrors ``0017_create_alert_notification_incident_sla_tables``'s
conventions: the table gets the ``BaseModel`` column set (id, created_at,
updated_at, soft-delete, audit, version) plus its own base-model indexes,
using the same ``_base_model_columns``/``_create_base_model_indexes``
helpers (duplicated here, not imported -- Alembic migrations are meant to
be self-contained snapshots rather than depending on other migration
modules).

One new table:

* ``analytics_snapshots`` -- a pre-computed rollup over
  ``[period_start, period_end]`` for one ``snapshot_type``
  (``ORG_DAILY_SUMMARY``/``LOCATION_DAILY_SUMMARY``/``PLATFORM_DAILY_SUMMARY``
  -- see ``app.domains.analytics.constants.AnalyticsSnapshotType``).
  ``organization_id``/``location_id`` are both nullable, ``SET NULL`` FKs
  (mirrors ``platform_events``' identical optional-scope convention from
  ``0016_create_monitoring_tables``). ``metrics`` is JSONB -- the actual
  computed numbers, shape documented on
  ``app.domains.analytics.models.AnalyticsSnapshot``.

No second ``analytics_cache`` table is created -- see that same model's
module docstring for why Redis (the same TTL'd-key pattern
``app.domains.rbac.cache.PermissionCache`` already establishes) is the
correct cache layer here, not a redundant SQL table.

No RBAC FK follow-up migration is needed -- this domain reuses RBAC's
already-seeded ``analytics.*``/``reports.*`` permission keys (a config-only
decision with no schema impact, see ``docs/analytics/DATABASE.md``).

Revision ID: 0018_create_analytics_tables
Revises: 0017_create_alert_notification_incident_sla_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0018_create_analytics_tables"
down_revision = "0017_create_alert_notification_incident_sla_tables"
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
    # -- analytics_snapshots -------------------------------------------------
    op.create_table(
        "analytics_snapshots",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("snapshot_type", sa.String(30), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("granularity", sa.String(20), nullable=False),
        sa.Column(
            "metrics",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("computation_duration_ms", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_analytics_snapshots_organization_id_organizations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_analytics_snapshots_location_id_locations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("analytics_snapshots")
    # Primary query pattern -- see app.domains.analytics.models
    # .AnalyticsSnapshot's own indexing-rationale docstring.
    op.create_index(
        "ix_analytics_snapshots_org_type_period_start",
        "analytics_snapshots",
        ["organization_id", "snapshot_type", "period_start"],
    )
    op.create_index(
        "ix_analytics_snapshots_location_id",
        "analytics_snapshots",
        ["location_id"],
    )
    op.create_index(
        "ix_analytics_snapshots_snapshot_type",
        "analytics_snapshots",
        ["snapshot_type"],
    )
    op.create_index(
        "ix_analytics_snapshots_period_start",
        "analytics_snapshots",
        ["period_start"],
    )
    op.create_index(
        "ix_analytics_snapshots_period_end",
        "analytics_snapshots",
        ["period_end"],
    )


def downgrade() -> None:
    op.drop_index("ix_analytics_snapshots_period_end", table_name="analytics_snapshots")
    op.drop_index(
        "ix_analytics_snapshots_period_start", table_name="analytics_snapshots"
    )
    op.drop_index(
        "ix_analytics_snapshots_snapshot_type", table_name="analytics_snapshots"
    )
    op.drop_index(
        "ix_analytics_snapshots_location_id", table_name="analytics_snapshots"
    )
    op.drop_index(
        "ix_analytics_snapshots_org_type_period_start",
        table_name="analytics_snapshots",
    )
    _drop_base_model_indexes("analytics_snapshots")
    op.drop_table("analytics_snapshots")

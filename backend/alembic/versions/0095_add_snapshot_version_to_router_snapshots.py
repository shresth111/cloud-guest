"""Router fleet redesign Wave 1 follow-up: ``router_snapshots.snapshot_version``.

The collector's section-JSON layout will evolve (Wave 2+ planner, wizard
UI); a persisted snapshot must say which shape it was written with so a
future reader can branch instead of guessing. One additive, nullable-free
column with a ``server_default`` -- the established zero-downtime pattern
for NOT NULL adds (see migration ``0083_add_wan_routing_mode_and_link_weight``):
existing rows (all written by the version-"1" collector) backfill to ``'1'``
in the same statement, no table rewrite beyond the metadata-only default
stamp, no lock held over a data migration.

Value source of truth: ``app.domains.provisioning_engine.planner.constants
.SNAPSHOT_SCHEMA_VERSION`` (duplicated here as a literal -- migrations are
self-contained snapshots by this repo's own convention, see ``0082``/``0086``
docstrings).

Revision ID: 0095_add_snapshot_version_to_router_snapshots
Revises: 0094_create_managed_router_resources_table
Create Date: 2026-08-21
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0095_add_snapshot_version_to_router_snapshots"
down_revision = "0094_create_managed_router_resources_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "router_snapshots",
        sa.Column(
            "snapshot_version",
            sa.String(length=20),
            nullable=False,
            server_default="1",
        ),
    )


def downgrade() -> None:
    op.drop_column("router_snapshots", "snapshot_version")

"""ISP ZONE-1: zone hierarchy (``isp_zone_nodes``).

Additive: one new table keyed by ``zone_id``; ``isp_zones`` is not altered.
``downgrade`` drops exactly this table.

``down_revision`` is the integ/isp-test head (0180_isp_fiber after the JAZE
lanes were chained into one line); re-point it if integ moves first.

Revision ID: 0181_isp_zone_tree
Revises: 0180_isp_fiber
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0181_isp_zone_tree"
down_revision = "0180_isp_fiber"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "isp_zone_nodes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "isp_organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "zone_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("isp_zones.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "parent_zone_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("isp_zones.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "uq_isp_zone_nodes_zone",
        "isp_zone_nodes",
        ["zone_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ix_isp_zone_nodes_isp_parent",
        "isp_zone_nodes",
        ["isp_organization_id", "parent_zone_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_isp_zone_nodes_isp_parent", table_name="isp_zone_nodes")
    op.drop_index("uq_isp_zone_nodes_zone", table_name="isp_zone_nodes")
    op.drop_table("isp_zone_nodes")

"""Create ``traffic_flow_windows`` and ``traffic_flow_ingest_state``.

NetFlow/IPFIX MVP (``app.domains.traffic_flow``, design in
``~/wyfy-ops/netflow/DESIGN.md``). Purely additive: two new tables, no
change to any existing row. Nothing writes to them unless
``CLOUDGUEST_TRAFFIC_FLOW_ENABLED`` is true.

``traffic_flow_windows`` -- one row per (router, source, 5-minute window),
unique on exactly that so a re-pulled window is ON CONFLICT DO NOTHING.
Indexed on ``window_start`` for the overview and the 7-day retention delete.

``traffic_flow_ingest_state`` -- single row (id = 1): the pull cursor and the
last pull's outcome.

Revision ID: 0152_create_traffic_flow_windows
Revises: 0151_merge_snmp_main_copy
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0152_create_traffic_flow_windows"
down_revision = "0151_merge_snmp_main_copy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_flow_windows",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("exporter_address", sa.String(length=45), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("packets_total", sa.BigInteger(), nullable=False),
        sa.Column("flows_total", sa.BigInteger(), nullable=False),
        sa.Column("bytes_internal", sa.BigInteger(), nullable=False),
        sa.Column("bytes_unclassified", sa.BigInteger(), nullable=False),
        sa.Column("bytes_other_talkers", sa.BigInteger(), nullable=False),
        sa.Column("bytes_other_destinations", sa.BigInteger(), nullable=False),
        sa.Column("talker_count", sa.Integer(), nullable=False),
        sa.Column("destination_count", sa.Integer(), nullable=False),
        sa.Column("top_talkers", postgresql.JSONB(), nullable=False),
        sa.Column("top_destinations", postgresql.JSONB(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name=op.f("fk_traffic_flow_windows_router_id_routers"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_traffic_flow_windows_organization_id_organizations"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name=op.f("fk_traffic_flow_windows_location_id_locations"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_traffic_flow_windows")),
        sa.UniqueConstraint(
            "router_id",
            "source",
            "window_start",
            name="uq_traffic_flow_windows_router_window",
        ),
    )
    op.create_index(
        "ix_traffic_flow_windows_window_start",
        "traffic_flow_windows",
        ["window_start"],
    )
    op.create_table(
        "traffic_flow_ingest_state",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("last_window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_pull_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_pull_ok", sa.Boolean(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "unknown_exporters",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_traffic_flow_ingest_state")),
    )


def downgrade() -> None:
    op.drop_table("traffic_flow_ingest_state")
    op.drop_index(
        "ix_traffic_flow_windows_window_start", table_name="traffic_flow_windows"
    )
    op.drop_table("traffic_flow_windows")

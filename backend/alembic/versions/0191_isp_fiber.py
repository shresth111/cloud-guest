"""ISP J22 fiber plant registry (ADDENDUM_05 §7, JAZE-6 part B).

Additive, ISP-owned tables only:

- ``isp_fiber_nodes``: OLT / pole / splitter / joint closure / ONT / other,
  lat/long, upstream ``parent_id`` route, optional ``port_count``.
- ``isp_fiber_port_assignments``: node port -> subscriber.

No pre-ISP table is touched. ``downgrade`` drops exactly these.

Chained on this lane's own ``0179_isp_pppoe`` so the lane has one head.
integ/isp-test: re-point ``0179_isp_pppoe.down_revision`` onto the integ head
before merging (lane rule); this file follows it unchanged.

Revision ID: 0191_isp_fiber
Revises: 0190_isp_pppoe
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0191_isp_fiber"
down_revision = "0190_isp_pppoe"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _base() -> list[sa.Column]:
    return [
        _uuid("id", primary_key=True, server_default=sa.text("gen_random_uuid()")),
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
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        _uuid("created_by", nullable=True),
        _uuid("updated_by", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _base_indexes(table: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_fiber_nodes",
        *_base(),
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("code", sa.String(40), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("address", sa.String(500), nullable=True),
        _uuid("parent_id", sa.ForeignKey("isp_fiber_nodes.id"), nullable=True),
        sa.Column("parent_port", sa.Integer(), nullable=True),
        sa.Column("port_count", sa.Integer(), nullable=True),
        sa.Column("spec", sa.String(120), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="active"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "kind in ('olt','pole','splitter','joint_closure','ont','other')",
            name="kind",
        ),
        sa.CheckConstraint(
            "status in ('active','planned','retired')",
            name="status",
        ),
        sa.CheckConstraint(
            "port_count is null or (port_count >= 1 and port_count <= 1024)",
            name="port_count",
        ),
        sa.CheckConstraint(
            "parent_port is null or parent_port >= 1",
            name="parent_port",
        ),
    )
    _base_indexes("isp_fiber_nodes")
    op.create_index(
        "ix_isp_fiber_nodes_isp_kind",
        "isp_fiber_nodes",
        ["isp_organization_id", "kind"],
    )
    op.create_index("ix_isp_fiber_nodes_parent", "isp_fiber_nodes", ["parent_id"])
    op.create_index(
        "uq_isp_fiber_nodes_isp_code",
        "isp_fiber_nodes",
        ["isp_organization_id", "code"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false and code is not null"),
    )
    op.create_index(
        "uq_isp_fiber_nodes_parent_port",
        "isp_fiber_nodes",
        ["parent_id", "parent_port"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false and parent_port is not null"),
    )

    op.create_table(
        "isp_fiber_port_assignments",
        *_base(),
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        _uuid("node_id", sa.ForeignKey("isp_fiber_nodes.id"), nullable=False),
        sa.Column("port_no", sa.Integer(), nullable=False),
        _uuid("subscriber_id", sa.ForeignKey("isp_subscribers.id"), nullable=False),
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("notes", sa.String(500), nullable=True),
        sa.CheckConstraint("port_no >= 1", name="port_no"),
    )
    _base_indexes("isp_fiber_port_assignments")
    op.create_index(
        "uq_isp_fiber_port_assignments_node_port",
        "isp_fiber_port_assignments",
        ["node_id", "port_no"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index(
        "uq_isp_fiber_port_assignments_subscriber",
        "isp_fiber_port_assignments",
        ["subscriber_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_table("isp_fiber_port_assignments")
    op.drop_table("isp_fiber_nodes")

"""INCIDENTS-1: outage incidents, their timeline and affected subscribers.

Additive: three new ISP-owned tables. ``downgrade`` drops exactly these.

Revision ID: 0202_isp_incidents
Revises: 0201_isp_collections
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0202_isp_incidents"
down_revision = "0201_isp_collections"
branch_labels = None
depends_on = None


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


def _org(name: str) -> sa.Column:
    return _uuid(
        name, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _base_indexes(table: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_incidents",
        *_base(),
        _org("isp_organization_id"),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("scope_kind", sa.String(12), nullable=False),
        _uuid("router_id", sa.ForeignKey("routers.id"), nullable=True),
        _uuid("fiber_node_id", sa.ForeignKey("isp_fiber_nodes.id"), nullable=True),
        _uuid("zone_id", sa.ForeignKey("isp_zones.id"), nullable=True),
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("scope_label", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("status", sa.String(14), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("identified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rfo_reason", sa.String(16), nullable=True),
        sa.Column("rfo_note", sa.Text(), nullable=True),
        sa.Column("affected_count", sa.Integer(), nullable=False),
        sa.Column("grace_hours", sa.Integer(), nullable=True),
        sa.Column("grace_applied_at", sa.DateTime(timezone=True), nullable=True),
    )
    _base_indexes("isp_incidents")
    op.create_index(
        "uq_isp_incidents_number",
        "isp_incidents",
        ["isp_organization_id", "number"],
        unique=True,
    )
    op.create_index(
        "ix_isp_incidents_isp_status",
        "isp_incidents",
        ["isp_organization_id", "status", "started_at"],
    )
    op.create_index("ix_isp_incidents_router", "isp_incidents", ["router_id"])
    op.create_index("ix_isp_incidents_fiber_node", "isp_incidents", ["fiber_node_id"])
    op.create_index("ix_isp_incidents_zone", "isp_incidents", ["zone_id"])

    op.create_table(
        "isp_incident_events",
        *_base(),
        _uuid(
            "incident_id",
            sa.ForeignKey("isp_incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(14), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    _base_indexes("isp_incident_events")
    op.create_index(
        "ix_isp_incident_events_incident",
        "isp_incident_events",
        ["incident_id", "occurred_at"],
    )

    op.create_table(
        "isp_incident_subscribers",
        *_base(),
        _uuid(
            "incident_id",
            sa.ForeignKey("isp_incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _uuid(
            "subscriber_id",
            sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _org("customer_organization_id"),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("node_name", sa.String(200), nullable=True),
        sa.Column("port_no", sa.Integer(), nullable=True),
        sa.Column("grace_status", sa.String(10), nullable=True),
        sa.Column("grace_detail", sa.String(255), nullable=True),
        sa.Column("grace_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outage_message", sa.String(12), nullable=True),
        sa.Column("restored_message", sa.String(12), nullable=True),
    )
    _base_indexes("isp_incident_subscribers")
    op.create_index(
        "uq_isp_incident_subscribers_pair",
        "isp_incident_subscribers",
        ["incident_id", "subscriber_id"],
        unique=True,
    )
    op.create_index(
        "ix_isp_incident_subscribers_subscriber",
        "isp_incident_subscribers",
        ["subscriber_id"],
    )


def downgrade() -> None:
    for table in (
        "isp_incident_subscribers",
        "isp_incident_events",
        "isp_incidents",
    ):
        op.drop_table(table)

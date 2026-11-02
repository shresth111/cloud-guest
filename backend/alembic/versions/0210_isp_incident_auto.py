"""SMALL-5: incidents auto-opened from router DOWN.

Additive: three new ISP-owned tables. ``downgrade`` drops exactly these.

Revision ID: 0210_isp_incident_auto
Revises: 0209_isp_revenue_snapshots
Create Date: 2026-11-02
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0210_isp_incident_auto"
down_revision = "0209_isp_revenue_snapshots"
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


def _org() -> sa.Column:
    return _uuid(
        "isp_organization_id",
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )


def _router() -> sa.Column:
    return _uuid(
        "router_id", sa.ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )


def _indexes(t: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{t}_{col}", t, [col])


def upgrade() -> None:
    t = "isp_incident_auto_settings"
    op.create_table(
        t,
        *_base(),
        _org(),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("down_minutes", sa.Integer(), nullable=False),
        sa.Column("up_minutes", sa.Integer(), nullable=False),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_incident_auto_settings_isp", t, ["isp_organization_id"], unique=True
    )

    t = "isp_incident_auto_routers"
    op.create_table(
        t,
        *_base(),
        _org(),
        _router(),
        sa.Column("observed_status", sa.String(6), nullable=False),
        sa.Column("observed_since", sa.DateTime(timezone=True), nullable=False),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_incident_auto_routers_router", t, ["router_id"], unique=True
    )
    op.create_index("ix_isp_incident_auto_routers_isp", t, ["isp_organization_id"])

    t = "isp_incident_autos"
    op.create_table(
        t,
        *_base(),
        _org(),
        _router(),
        _uuid(
            "customer_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _uuid(
            "incident_id",
            sa.ForeignKey("isp_incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("down_since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "auto_resolved", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    _indexes(t)
    op.create_index("uq_isp_incident_autos_incident", t, ["incident_id"], unique=True)
    op.create_index(
        "uq_isp_incident_autos_router_open",
        t,
        ["router_id"],
        unique=True,
        postgresql_where=sa.text("closed_at IS NULL"),
    )
    op.create_index("ix_isp_incident_autos_isp", t, ["isp_organization_id"])


def downgrade() -> None:
    op.drop_table("isp_incident_autos")
    op.drop_table("isp_incident_auto_routers")
    op.drop_table("isp_incident_auto_settings")

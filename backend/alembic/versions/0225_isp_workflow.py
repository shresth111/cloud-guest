"""RAKESH-FS: franchisee zones, router<->zones, subscriber router, zone packages.

Additive: four new ISP-owned link tables. ``downgrade`` drops exactly these.

Revision ID: 0225_isp_workflow
Revises: 0224_isp_p1_zone_coupon_rights
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0225_isp_workflow"
down_revision = "0224_isp_p1_zone_coupon_rights"
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


def _fk(name: str, target: str) -> sa.Column:
    return _uuid(name, sa.ForeignKey(target, ondelete="CASCADE"), nullable=False)


def _indexes(t: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{t}_{col}", t, [col])


def upgrade() -> None:
    t = "isp_franchisee_zones"
    op.create_table(
        t,
        *_base(),
        _fk("isp_organization_id", "organizations.id"),
        _fk("user_id", "users.id"),
        _fk("zone_id", "isp_zones.id"),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_franchisee_zones_user_zone", t, ["user_id", "zone_id"], unique=True
    )
    op.create_index(
        "ix_isp_franchisee_zones_isp_user", t, ["isp_organization_id", "user_id"]
    )

    t = "isp_router_zones"
    op.create_table(
        t,
        *_base(),
        _fk("isp_organization_id", "organizations.id"),
        _fk("router_id", "routers.id"),
        _fk("zone_id", "isp_zones.id"),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_router_zones_router_zone", t, ["router_id", "zone_id"], unique=True
    )
    op.create_index(
        "ix_isp_router_zones_isp_zone", t, ["isp_organization_id", "zone_id"]
    )

    t = "isp_subscriber_routers"
    op.create_table(
        t,
        *_base(),
        _fk("isp_organization_id", "organizations.id"),
        _fk("subscriber_id", "isp_subscribers.id"),
        _fk("router_id", "routers.id"),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_subscriber_routers_subscriber", t, ["subscriber_id"], unique=True
    )
    op.create_index("ix_isp_subscriber_routers_router", t, ["router_id"])

    t = "isp_zone_packages"
    op.create_table(
        t,
        *_base(),
        _fk("isp_organization_id", "organizations.id"),
        _fk("zone_id", "isp_zones.id"),
        _fk("package_id", "isp_packages.id"),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_zone_packages_zone_pkg", t, ["zone_id", "package_id"], unique=True
    )
    op.create_index("ix_isp_zone_packages_isp", t, ["isp_organization_id"])


def downgrade() -> None:
    op.drop_table("isp_zone_packages")
    op.drop_table("isp_subscriber_routers")
    op.drop_table("isp_router_zones")
    op.drop_table("isp_franchisee_zones")

"""RAKESH-P1 P1-1: device count + MAC binding on speed templates.

Additive: one new ISP-owned table keyed by ``speed_group_id``. No existing
table is altered. ``downgrade`` drops exactly this table.

Revision ID: 0221_isp_p1_template_rules
Revises: 0198_isp_incident_auto
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0221_isp_p1_template_rules"
down_revision = "0198_isp_incident_auto"
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


def _indexes(t: str) -> None:
    for col in _BASE_INDEXED:
        op.create_index(f"ix_{t}_{col}", t, [col])


def upgrade() -> None:
    t = "isp_speed_group_device_rules"
    op.create_table(
        t,
        *_base(),
        _org(),
        _uuid(
            "speed_group_id",
            sa.ForeignKey("isp_speed_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("max_devices", sa.SmallInteger(), nullable=False, server_default="1"),
        sa.Column(
            "mac_bind_count", sa.SmallInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "mac_restriction", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("max_simultaneous", sa.SmallInteger(), nullable=True),
    )
    _indexes(t)
    op.create_index(
        "uq_isp_speed_group_device_rules_group",
        t,
        ["speed_group_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index("ix_isp_speed_group_device_rules_isp", t, ["isp_organization_id"])


def downgrade() -> None:
    op.drop_table("isp_speed_group_device_rules")

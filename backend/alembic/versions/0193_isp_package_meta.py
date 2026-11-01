"""PKG-2: package type + connection type, keyed by package_id.

Additive: one new table ``isp_package_meta``; ``isp_packages`` is not
altered. ``downgrade`` drops exactly this table.

Revision ID: 0193_isp_package_meta
Revises: 0192_isp_zone_tree
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0193_isp_package_meta"
down_revision = "0192_isp_zone_tree"
branch_labels = None
depends_on = None

_T = "isp_package_meta"


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def upgrade() -> None:
    op.create_table(
        _T,
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
        _uuid("isp_organization_id", sa.ForeignKey("organizations.id"), nullable=False),
        _uuid("package_id", sa.ForeignKey("isp_packages.id"), nullable=False),
        sa.Column("package_type", sa.String(12), nullable=True),
        sa.Column("connection_type", sa.String(12), nullable=True),
        sa.CheckConstraint(
            "package_type is null or package_type in "
            "('home','commercial','sme','enterprise')",
            name="package_type",
        ),
        sa.CheckConstraint(
            "connection_type is null or connection_type in "
            "('wireless','fiber','ethernet')",
            name="connection_type",
        ),
    )
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{_T}_{col}", _T, [col])
    op.create_index(
        "uq_isp_package_meta_package",
        _T,
        ["package_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index("ix_isp_package_meta_isp", _T, ["isp_organization_id"])


def downgrade() -> None:
    op.drop_table(_T)

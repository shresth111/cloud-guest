"""BILL-2: per-zone invoice branding (isp_zone_branding), keyed by zone_id.

Additive: one new table; ``isp_zones`` / ``isp_zone_profiles`` untouched.
``downgrade`` drops exactly this table.

Revision ID: 0183_isp_zone_branding
Revises: 0182_isp_package_meta
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0183_isp_zone_branding"
down_revision = "0182_isp_package_meta"
branch_labels = None
depends_on = None

_T = "isp_zone_branding"


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
        _uuid("zone_id", sa.ForeignKey("isp_zones.id"), nullable=False),
        sa.Column("invoice_name", sa.String(120), nullable=True),
        sa.Column("bank_name", sa.String(120), nullable=True),
        sa.Column("bank_account_name", sa.String(120), nullable=True),
        sa.Column("bank_account_number", sa.String(34), nullable=True),
        sa.Column("bank_ifsc", sa.String(11), nullable=True),
        sa.Column("bank_branch", sa.String(120), nullable=True),
        sa.Column("upi_vpa", sa.String(100), nullable=True),
    )
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{_T}_{col}", _T, [col])
    op.create_index(
        "uq_isp_zone_branding_zone",
        _T,
        ["zone_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index("ix_isp_zone_branding_isp", _T, ["isp_organization_id"])


def downgrade() -> None:
    op.drop_table(_T)

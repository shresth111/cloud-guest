"""CAF-2 workbench: ``isp_caf_extras`` + ``isp_caf_profiles`` (additive).

New ISP-owned tables only; no existing table is altered. ``downgrade`` drops
exactly these two.

Revision ID: 0182_isp_caf_workbench
Revises: 0181_isp_zone_tree
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0182_isp_caf_workbench"
down_revision = "0181_isp_zone_tree"
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


def _base_indexes(table: str) -> None:
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{table}_{col}", table, [col])


def upgrade() -> None:
    op.create_table(
        "isp_caf_extras",
        *_base(),
        _uuid(
            "isp_organization_id",
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        _uuid("subscriber_id", sa.ForeignKey("isp_subscribers.id"), nullable=True),
        _uuid("lead_id", sa.ForeignKey("isp_leads.id"), nullable=True),
        sa.Column("applicant_category", sa.String(20), nullable=False),
        sa.Column("applicant_category_other", sa.String(60), nullable=True),
        sa.Column("father_or_spouse_name", sa.String(200), nullable=True),
        sa.Column("plot_no", sa.String(60), nullable=True),
        sa.Column("locality", sa.String(120), nullable=True),
        sa.Column("district", sa.String(100), nullable=True),
        sa.CheckConstraint(
            "subscriber_id IS NOT NULL OR lead_id IS NOT NULL",
            name="ck_isp_caf_extras_subject",
        ),
    )
    _base_indexes("isp_caf_extras")
    op.create_index(
        "uq_isp_caf_extras_subscriber",
        "isp_caf_extras",
        ["subscriber_id"],
        unique=True,
        postgresql_where=sa.text("subscriber_id IS NOT NULL AND is_deleted = false"),
    )
    op.create_index(
        "uq_isp_caf_extras_lead",
        "isp_caf_extras",
        ["lead_id"],
        unique=True,
        postgresql_where=sa.text(
            "lead_id IS NOT NULL AND subscriber_id IS NULL AND is_deleted = false"
        ),
    )

    op.create_table(
        "isp_caf_profiles",
        *_base(),
        _uuid(
            "isp_organization_id",
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("signatory_name", sa.String(120), nullable=True),
        sa.Column("signatory_designation", sa.String(120), nullable=True),
        sa.Column("stamp_storage_key", sa.String(500), nullable=True),
        sa.Column("stamp_content_type", sa.String(40), nullable=True),
        sa.Column("stamp_size_bytes", sa.Integer(), nullable=True),
    )
    _base_indexes("isp_caf_profiles")
    op.create_index(
        "uq_isp_caf_profiles_isp",
        "isp_caf_profiles",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_table("isp_caf_profiles")
    op.drop_table("isp_caf_extras")

"""COMMS-2b: rendered WhatsApp parameters per sent message.

Additive: one new table keyed by ``isp_message_log.id``; the JAZE-4 log is
not altered. ``downgrade`` drops exactly this table.

Revision ID: 0187_isp_comms_2b
Revises: 0186_isp_franchise
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0187_isp_comms_2b"
down_revision = "0186_isp_franchise"
branch_labels = None
depends_on = None

_T = "isp_message_contents"


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
        _uuid(
            "isp_organization_id",
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _uuid(
            "message_log_id",
            sa.ForeignKey("isp_message_log.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("template_name", sa.String(512), nullable=True),
        sa.Column("language", sa.String(15), nullable=True),
        sa.Column(
            "parameters",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{_T}_{col}", _T, [col])
    op.create_index("uq_isp_message_contents_log", _T, ["message_log_id"], unique=True)


def downgrade() -> None:
    op.drop_table(_T)

"""IPDR index tables: ``ipdr_day_files`` and ``ipdr_day_subjects``.

The IPDR rows themselves are archived as gzip NDJSON (S3 ``ipdr/`` prefix,
2-year Object Lock); Postgres keeps one row per archived (location, IST day)
and the hashed subjects of each day. See app.domains.ipdr.

Chained on 0168 (firewall logging, PR #422).
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0169_create_ipdr_tables"
down_revision = "0168_router_remote_logging_firewall_logging"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ipdr_day_files",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=True),
            primary_key=True,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("store", sa.String(length=8), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("row_count", sa.BigInteger(), nullable=False),
        sa.Column("unknown_user_rows", sa.BigInteger(), nullable=False),
        sa.Column("derived_translation_rows", sa.BigInteger(), nullable=False),
        sa.Column(
            "records_incomplete",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "location_id", "day", name="uq_ipdr_day_files_location_day"
        ),
    )
    op.create_index(
        "ix_ipdr_day_files_org_day", "ipdr_day_files", ["organization_id", "day"]
    )
    op.create_table(
        "ipdr_day_subjects",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=True),
            primary_key=True,
        ),
        sa.Column(
            "day_file_id",
            sa.BigInteger(),
            sa.ForeignKey("ipdr_day_files.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.UniqueConstraint(
            "day_file_id", "kind", "digest", name="uq_ipdr_day_subjects_key"
        ),
    )
    op.create_index(
        "ix_ipdr_day_subjects_lookup", "ipdr_day_subjects", ["kind", "digest"]
    )


def downgrade() -> None:
    op.drop_index("ix_ipdr_day_subjects_lookup", table_name="ipdr_day_subjects")
    op.drop_table("ipdr_day_subjects")
    op.drop_index("ix_ipdr_day_files_org_day", table_name="ipdr_day_files")
    op.drop_table("ipdr_day_files")

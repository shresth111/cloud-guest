"""Bring-your-own providers for guest login codes (OTP), on the marketing table.

``org_marketing_providers`` (0135) already holds a venue's own SMS/WhatsApp/
email account, Fernet-encrypted, write-only, verified before use. Guest login
codes need exactly that, so the table is generalised instead of copied:

* ``purpose`` (NOT NULL, server default ``'marketing'`` -- the backfill for
  every existing row): ``marketing`` = campaigns, ``otp`` = guest login codes;
* the one-live-row unique index moves from (organization, channel) to
  (organization, purpose, channel), so a venue can hold one campaign account
  and one login-code account per channel;
* ``configured_by_platform``: the Wyfy team set the row up from the Master
  console on the venue's behalf;
* ``fallback_count`` / ``last_fallback_at`` / ``last_fallback_error``: login
  codes that failed on the venue's account and went out through the
  platform default instead (the dashboard's fallback warning).

Downgrade refuses to run while ``otp`` rows exist: dropping ``purpose`` would
turn them into campaign accounts and collide on the old unique index. Delete
them first (they are credentials the venue can re-enter).

Revision ID: 0167_org_provider_purpose
Revises: 0166_add_review_prompt_columns_to_guest_sessions
Create Date: 2026-10-18
"""

import sqlalchemy as sa

from alembic import op

revision = "0167_org_provider_purpose"
down_revision = "0166_add_review_prompt_columns_to_guest_sessions"
branch_labels = None
depends_on = None

TABLE = "org_marketing_providers"


def upgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column("purpose", sa.String(16), nullable=False, server_default="marketing"),
    )
    op.add_column(
        TABLE,
        sa.Column(
            "configured_by_platform",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        TABLE,
        sa.Column("fallback_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        TABLE,
        sa.Column("last_fallback_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        TABLE, sa.Column("last_fallback_error", sa.String(500), nullable=True)
    )
    op.drop_index("uq_omp_org_channel", table_name=TABLE)
    op.create_index(
        "uq_omp_org_purpose_channel",
        TABLE,
        ["organization_id", "purpose", "channel"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    remaining = bind.execute(
        sa.text(f"SELECT count(*) FROM {TABLE} WHERE purpose <> 'marketing'")
    ).scalar()
    if remaining:
        raise RuntimeError(
            f"{remaining} login-code (purpose='otp') provider rows exist; "
            "delete them before downgrading past 0167"
        )
    op.drop_index("uq_omp_org_purpose_channel", table_name=TABLE)
    op.create_index(
        "uq_omp_org_channel",
        TABLE,
        ["organization_id", "channel"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    for column in (
        "last_fallback_error",
        "last_fallback_at",
        "fallback_count",
        "configured_by_platform",
        "purpose",
    ):
        op.drop_column(TABLE, column)

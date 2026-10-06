"""Add ``captive_portal_configs.require_guest_email`` and
``captive_portal_configs.post_login_sequence``.

``require_guest_email`` -- the email twin of 0143's ``require_guest_name``:
when true, an OTP guest with no email on file is asked for one on the
sign-in details screen and the network stays shut for that session until it
is stored. **Defaults false** for every row: requiring a contact channel is
a per-venue decision, not a platform default. An email-OTP guest satisfies
it automatically (their identifier is an email).

``post_login_sequence`` -- the venue's ordered post-login steps plus the
final destination, as JSONB (``{"steps": [...], "finish": ...}``). Nullable
and left NULL on every existing row: NULL means "derive the old single
choice from post_login_html / redirect_url", so no venue's guests see a
different flow on deploy.

Revision ID: 0148_add_require_guest_email_and_post_login_sequence
Revises: 0147_merge_main_require_guest_name
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0148_add_require_guest_email_and_post_login_sequence"
down_revision = "0147_merge_main_require_guest_name"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "require_guest_email",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "post_login_sequence",
            postgresql.JSONB(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "post_login_sequence")
    op.drop_column("captive_portal_configs", "require_guest_email")

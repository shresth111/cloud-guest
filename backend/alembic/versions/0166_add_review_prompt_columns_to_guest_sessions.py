"""Guest sessions: when the "Rate us on Google" page was shown, and tapped.

Adds two nullable timestamps to ``guest_sessions``:

* ``review_prompt_shown_at`` -- the post-login review page was shown in this
  session;
* ``review_link_opened_at`` -- the guest tapped through to the venue's Google
  review link from it.

Both live on the session because the session carries ``location_id`` while
``guests`` is per organization. That gives "already asked at this location"
and per-location counts from one table. A partial index on
``(location_id, guest_id)`` covers only rows that hold either stamp, so it
stays small: almost every session has neither.

Nullable with no default, so existing rows need no rewrite. Idempotent
(``IF NOT EXISTS``).

Revision ID: 0166_add_review_prompt_columns_to_guest_sessions
Revises: 0165_traffic_flow_platform_hosts
Create Date: 2026-10-15
"""

from __future__ import annotations

from alembic import op

revision = "0166_add_review_prompt_columns_to_guest_sessions"
down_revision = "0165_traffic_flow_platform_hosts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE guest_sessions "
        "ADD COLUMN IF NOT EXISTS review_prompt_shown_at TIMESTAMPTZ NULL"
    )
    op.execute(
        "ALTER TABLE guest_sessions "
        "ADD COLUMN IF NOT EXISTS review_link_opened_at TIMESTAMPTZ NULL"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_guest_sessions_review_activity "
        "ON guest_sessions (location_id, guest_id) "
        "WHERE review_prompt_shown_at IS NOT NULL "
        "OR review_link_opened_at IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_guest_sessions_review_activity")
    op.execute("ALTER TABLE guest_sessions DROP COLUMN IF EXISTS review_link_opened_at")
    op.execute(
        "ALTER TABLE guest_sessions DROP COLUMN IF EXISTS review_prompt_shown_at"
    )

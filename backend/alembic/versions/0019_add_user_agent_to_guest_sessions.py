"""Add ``user_agent`` to ``guest_sessions`` (BE-012 Part 2: Super Admin +
Organization + Location Dashboards).

Narrow, additive column: the raw ``User-Agent`` request header, captured
(best-effort, nullable) at ``app.domains.guest.service.GuestService
.login_via_otp``/``login_via_voucher`` -- see
``app.domains.guest.models.GuestSession.user_agent``'s docstring for the
full write-up on why this was judged worth doing for real (a cheap,
narrow, additive hook, following the exact same discipline BE-011 Part 1's
``HeartbeatLog`` hook and BE-011 Part 3's real-time broadcast hook already
established), and ``docs/analytics/FLOW.md`` for how
``app.domains.analytics`` classifies this raw string into device/browser/OS
buckets via real SQL at read time (never a pre-parsed column, so a future,
better heuristic never needs a backfill migration).

No index: this column is never filtered/joined on, only classified via
``CASE``/regex matching and aggregated by the analytics dashboard read path
(see ``app.domains.analytics.repository.AnalyticsRepository
.get_user_agent_breakdown``) -- an index on a free-form, high-cardinality
text column would cost real write-time overhead for a read pattern that
never does an equality/range lookup against it.

Revision ID: 0019_add_user_agent_to_guest_sessions
Revises: 0018_create_analytics_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0019_add_user_agent_to_guest_sessions"
down_revision = "0018_create_analytics_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_sessions",
        sa.Column("user_agent", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guest_sessions", "user_agent")

"""Add ``accept_language`` to ``guest_sessions`` (BE-012 Part 3: Router +
Network + Guest + Authentication Analytics).

Narrow, additive column: the raw ``Accept-Language`` request header,
captured (best-effort, nullable) at ``app.domains.guest.service.GuestService
.login_via_otp``/``login_via_voucher`` -- the *exact same* judgment call
already made for ``guest_sessions.user_agent`` in
``0019_add_user_agent_to_guest_sessions`` (BE-012 Part 2): both endpoints
already receive a ``Request`` object, so reading one more header at the same
two call sites is a narrow, cheap, honest capture. See
``app.domains.guest.models.GuestSession.accept_language``'s docstring and
``docs/analytics/FLOW.md``'s "Language Statistics" section for the full
write-up.

No index: this column is never filtered/joined on, only classified (the
primary language tag extracted from the raw header value) via SQL at
dashboard read time (see ``app.domains.analytics.repository
.AnalyticsRepository.get_language_breakdown``) -- an index on a free-form,
low-cardinality-but-never-looked-up-by-equality text column would cost real
write-time overhead for a read pattern that never does an equality/range
lookup against it, the identical reasoning ``user_agent``'s own migration
already documents.

Revision ID: 0020_add_accept_language_to_guest_sessions
Revises: 0019_add_user_agent_to_guest_sessions
Create Date: 2026-07-19
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0020_add_accept_language_to_guest_sessions"
down_revision = "0019_add_user_agent_to_guest_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_sessions",
        sa.Column("accept_language", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guest_sessions", "accept_language")

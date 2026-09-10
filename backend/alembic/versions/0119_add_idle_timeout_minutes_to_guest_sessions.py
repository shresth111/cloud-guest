"""Add ``idle_timeout_minutes`` to ``guest_sessions``.

The venue's idle timeout, in minutes, as it stood at the moment this
session started -- the value this platform sends as the RFC 2865 s5.28
``Idle-Timeout`` reply attribute on the session's Access-Accept.

WHY THE COLUMN EXISTS AT ALL, RATHER THAN A LOOKUP AT REPLY TIME

``RadiusService.authorize`` runs on every re-authorization, not just the
first, and a NAS re-authorizes an already-connected device repeatedly.
Resolving the policy there would mean an operator who shortens the venue's
idle timeout at 3pm silently shortens the allowance of a guest who
connected at 2pm, mid-session, on the next keepalive. ``guest_sessions``
already carries ``session_timeout_minutes`` for precisely this reason (see
``app.domains.guest.service``'s module docstring on "copied, not
referenced", which it in turn inherits from ``Voucher.expires_at``); this
column is that same decision applied to the second time dimension.

It is also what lets ``GET /guest/session/last-ended`` tell a guest who was
idled out *which* number ended their session, instead of whichever number
happens to be configured by the time they read the screen.

WHY NULLABLE, AND WHY NO BACKFILL

NULL means "no idle timeout was recorded for this session". Every row
written before this migration is in that state and is left there
deliberately -- backfilling today's configured value onto a historical
session would be inventing a fact about a session that has already ended,
and the only consumer of a historical row is the last-ended screen, which
is content to say less rather than say something it cannot know.

Readers treat NULL as "send no ``Idle-Timeout`` attribute", which leaves
the NAS's own hotspot-profile value standing -- exactly the behaviour every
session had before this platform sent the attribute at all. So a session
that is still ACTIVE across the deploy does not change behaviour; it simply
keeps the device-side default it already had until it ends.

Revision ID: 0119_add_idle_timeout_minutes_to_guest_sessions
Revises: 0118_add_router_reachability_columns
Create Date: 2026-09-07
"""

import sqlalchemy as sa

from alembic import op

revision = "0119_add_idle_timeout_minutes_to_guest_sessions"
down_revision = "0118_add_router_reachability_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_sessions",
        sa.Column("idle_timeout_minutes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guest_sessions", "idle_timeout_minutes")

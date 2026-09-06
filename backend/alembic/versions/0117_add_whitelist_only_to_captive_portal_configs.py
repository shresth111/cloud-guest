"""Add whitelist_only_* columns to captive_portal_configs -- the schema
half of per-property whitelist-only mode, shipped dark.

A venue that turns this on wants exactly one thing: only the guests on its
Always Allowed list get internet, and everybody else still reaches the
captive portal and is refused there. The portal stays the chokepoint, so
nothing on the device changes -- which is the whole reason the switch
belongs on this table and not on the policy domain. This row is already
org-scoped with a nullable ``location_id`` resolved most-specific-wins,
and it is already resolved on the login path *before* the access gate
runs, so the flag costs no extra query and has no new way to fail. It is
the identical shape ``business_hours_enabled`` /
``business_hours_closed_message`` (0068) already ship in.

``whitelist_only_enabled`` is NOT NULL with a ``false`` server default:
every existing config keeps today's behaviour, and this migration is a
no-op for every live venue. ``whitelist_only_denied_message`` is nullable
-- null means the venue wrote no copy of its own and the frontend supplies
the generic default, exactly as ``business_hours_closed_message`` already
works. A server-side default string would be indistinguishable from a
venue that deliberately typed the same words.

No gate logic ships with this migration. The columns are written, read
back by the dashboard and validated (an org-default config -- ``location_id
IS NULL`` -- may not carry the flag, since that would switch on every
property at once); nothing consumes ``whitelist_only_enabled`` on the
login path yet.

Numbering: this was written against ``0113``, the then-head on
``origin/main``, while ``0114``-``0116`` (an unrelated post-connect-ask /
profile-prompt / consent-backfill set) were in flight on no branch yet --
so it took ``0117`` rather than collide, and its original
``down_revision`` pointed at ``0113``.

That set landed first, and this revision was then merged without the
rebase its own warning called for, which is exactly how ``main`` came to
have two heads: ``0116`` and this one. ``down_revision`` is now
``0116_backfill_guest_consent_terms_version``, restoring a single
straight-line chain. Only the pointer moved -- ``0114`` adds its own
columns to this same ``captive_portal_configs`` table, but the two sets
are disjoint, so no upgrade() body changed and either order would have
applied cleanly.

Revision ID: 0117_add_whitelist_only_to_captive_portal_configs
Revises: 0116_backfill_guest_consent_terms_version
Create Date: 2026-09-06
"""

import sqlalchemy as sa

from alembic import op

revision = "0117_add_whitelist_only_to_captive_portal_configs"
down_revision = "0116_backfill_guest_consent_terms_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "whitelist_only_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("whitelist_only_denied_message", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "whitelist_only_denied_message")
    op.drop_column("captive_portal_configs", "whitelist_only_enabled")

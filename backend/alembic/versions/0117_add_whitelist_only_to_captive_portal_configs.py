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

Numbering: ``0113`` is the latest revision on ``origin/main`` and is this
revision's parent. ``0114``-``0116`` were already claimed at the time this
was written by concurrent work that is **not on any branch yet** (an
unrelated post-connect-ask / profile-prompt / consent-backfill set), so
``ls alembic/versions`` on a fresh checkout does not show them and this
takes ``0117`` rather than collide. The gap is a numbering artifact, not a
branch: the chain here is straight-line off ``0113``.

**Whoever merges second must check, not assume.** If that set lands first,
rebase this ``down_revision`` onto whatever is then head, or Alembic gets
two heads (this repo has been there -- see the ``fix/alembic-two-heads``
branch). Note in particular that ``0114`` adds its own columns to this
same ``captive_portal_configs`` table. The columns are disjoint, so there
is no data conflict and either order applies cleanly -- it is purely the
``down_revision`` pointer that has to be made to agree.

Revision ID: 0117_add_whitelist_only_to_captive_portal_configs
Revises: 0113_create_router_rogue_dhcp_statuses_table
Create Date: 2026-09-06
"""

import sqlalchemy as sa

from alembic import op

revision = "0117_add_whitelist_only_to_captive_portal_configs"
down_revision = "0113_create_router_rogue_dhcp_statuses_table"
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

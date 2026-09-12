"""Six columns on ``captive_portal_configs`` for what a guest is asked
*after* the gate opens: ``collect_guest_name``, ``collect_guest_email``,
``review_card_enabled``, ``review_url``, ``guest_feedback_enabled``,
``feedback_dwell_minutes``.

Everything here governs ``/portal/session`` -- the screen a guest reaches
once the RADIUS session is authorised and the NAS gate is open. None of it
can change whether, how fast, or how long anyone is connected. That is the
property the whole design rests on, so it is worth saying at the schema
layer too.

## The defaults: new rows off, existing rows unchanged

``collect_guest_name`` and ``collect_guest_email`` are **backfilled true
for every row that exists when this runs**, and default **false for rows
created afterwards**.

An earlier draft of this migration defaulted them false everywhere, on the
reasoning that the venue -- not this platform -- is the Data Fiduciary
under India's DPDP Act for a guest's name and email, so a migration must
not switch personal-data collection on for them. That reasoning is sound
about *new* venues and is why new rows still start false. It is wrong
about existing ones, for two reasons.

The first is that the card **is already on, everywhere, today**:
``GuestProfileNudge`` renders both fields unconditionally at every venue.
Switching it off by ``ALTER TABLE`` is not declining to make a decision on
the venue's behalf; it is making the opposite decision on their behalf,
and deleting a live feature with no notice to anybody.

The second is worse and is the reason this is not merely a preference.
``GuestService.update_guest_profile`` now rejects a write to a
switched-off field, and the shipped component catches that 400, discards
it silently, and plays its success path anyway
(``GuestProfileNudge.tsx`` -- ``catch {}`` then ``finally { finish() }``).
A false backfill therefore does not stop collection cleanly. It gives
every guest at every venue a form that accepts their name, throws it
away, and tells them it worked. That is a worse outcome under DPDP than
either honest state, because the guest is told their data was taken.

What makes the collection lawful is the notice shown to the guest, not
the value of this column. The notice is what is actually missing, and a
flag cannot stand in for it. (What a lawful record needs, and what this
platform stores today, is written up on
``GuestService._resolve_terms_version``, which lands in this same change
and starts stamping new consents with the terms they were given.)

``review_card_enabled``, ``guest_feedback_enabled`` and ``review_url``
default false/null with no such tension: none of those cards exists yet,
and the review card does nothing at all without ``review_url``.

``feedback_dwell_minutes`` defaults to 25 for every row, new and existing
-- the same number the guest portal already clamps to when the field is
absent, so the column starts out agreeing with the client that will read
it.
It is inert until ``guest_feedback_enabled`` is turned on, so the value
carried by existing rows is never read.

## Why on this table

``captive_portal_configs`` already resolves per location with an
org-wide fallback (``location_id`` nullable), which is exactly the right
grain: a chain with one Google profile per branch gets one row per branch
for free. And the resolve endpoint already ships these rows to the portal,
so the guest surface gets all four fields with no new plumbing.

⚠ ``GET /captive-portal/resolve`` is unauthenticated and emits every column
on this model. A review link is public information -- it is a URL the venue
wants the world to click -- so it belongs here. The next person adding a
column to this table should check that theirs does too.

## ``review_url`` is nullable and stays nullable

Null means no card. Not a disabled card, not a placeholder, and never a
fallback to a Maps search for the venue's name, which would land guests on
the wrong branch of a chain. There is no sensible default value for a link
only the merchant can produce.

``downgrade`` drops all six. The backfill goes with the columns it wrote,
so there is nothing left to un-say.

Revision ID: 0114_add_post_connect_ask_columns_to_captive_portal_configs
Revises: 0113_create_router_rogue_dhcp_statuses_table
Create Date: 2026-09-06
"""

import sqlalchemy as sa

from alembic import op

revision = "0114_add_post_connect_ask_columns_to_captive_portal_configs"
# Reparented onto 0117, not the other way round, and the direction is the
# whole point.
#
# 0114 and 0117 were written in parallel worktrees and both took
# 0113 as their parent, so `alembic upgrade head` found two heads and every
# backend deploy from 13:54 onward failed at container boot -- five in a row,
# with the frontend deploying normally the whole time.
#
# The obvious repair is to hang 0117 off 0116 and keep the filename order.
# That would have been wrong, and only reading production said so:
# `alembic_version` is already at **0117**. It applied cleanly at 12:12,
# when 0117 was the only new revision on main; 0114-0116 arrived at 13:54
# and have never run. Pointing 0117 at 0116 would leave alembic believing
# everything below its current revision was applied, and these three columns
# would never be created -- a silent no-op instead of a loud failure.
#
# So the applied revision stays where it is and the unapplied ones queue
# behind it. The filename numbers now read out of order against the graph;
# the graph is what alembic follows, and correctness beat tidiness here.
down_revision = "0117_add_whitelist_only_to_captive_portal_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "collect_guest_name",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "collect_guest_email",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "review_card_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("review_url", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "guest_feedback_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "feedback_dwell_minutes",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("25"),
        ),
    )

    # The backfill, and the only statement in this file that changes
    # behaviour for anybody. ``add_column`` above has just written false
    # into every existing row; this puts the two profile-capture flags
    # back to what those venues actually have today, which is on. The
    # ``server_default`` stays false, so rows created after this point
    # start off. See the module docstring for why the split is this way
    # round and not the other.
    op.execute(
        """
        UPDATE captive_portal_configs
           SET collect_guest_name = true,
               collect_guest_email = true
        """
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "feedback_dwell_minutes")
    op.drop_column("captive_portal_configs", "guest_feedback_enabled")
    op.drop_column("captive_portal_configs", "review_url")
    op.drop_column("captive_portal_configs", "review_card_enabled")
    op.drop_column("captive_portal_configs", "collect_guest_email")
    op.drop_column("captive_portal_configs", "collect_guest_name")

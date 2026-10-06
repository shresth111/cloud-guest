"""Add ``captive_portal_configs.require_guest_name`` -- name required at
sign-in, ON by default for every venue.

What it does: when true, a guest who signs in with a one-time code (SMS,
WhatsApp or email OTP) and has no name on file is shown a single "Your
name" screen right after the code verifies, and the network is not opened
for that session until the name is stored. The server enforces it at every
step that opens the network (RADIUS Authorize, the router agent's
``/agent/authorized-macs`` bypass list, and
``POST /network-integrations/portal/authorize`` and its RADIUS sibling) --
see ``GuestService.session_awaits_required_name``.

**Default true, for existing rows AND new ones.** This is an owner
decision, and it changes live behaviour at every venue on deploy: every
OTP guest without a stored name sees the name screen once. A venue can turn
it off in Portal settings.

``require_guest_name`` implies ``collect_guest_name`` (the venue is the
Data Fiduciary for the name under DPDP; requiring it while not collecting
it is incoherent), so the backfill also switches ``collect_guest_name`` on
wherever ``require_guest_name`` is now true -- which, on this upgrade, is
every row. ``CaptivePortalService.update_config`` keeps the two consistent
afterwards.

Revision chaining: two open PRs (#341 ``0143_create_radius_nas_learned_
addresses`` and #338 ``0143_add_radius_nas_radsec_identity``) also chain
off 0142. Whichever merges second must re-point its ``down_revision`` so
``alembic heads`` stays single.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0143_add_require_guest_name_to_captive_portal_configs"
down_revision = "0142_create_instant_on_poller_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default true so a row created by ANY path -- the ORM, a raw
    # INSERT in a script, a seed -- starts with the owner's default.
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "require_guest_name",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    # add_column has already written true into every existing row. Keep
    # the implication coherent: required means collected.
    op.execute(
        """
        UPDATE captive_portal_configs
           SET collect_guest_name = true
         WHERE require_guest_name = true
        """
    )


def downgrade() -> None:
    # collect_guest_name is deliberately not reverted: the backfill cannot
    # tell which rows had it on before, and leaving collection on is the
    # pre-0143 behaviour of 0114's own backfill.
    op.drop_column("captive_portal_configs", "require_guest_name")

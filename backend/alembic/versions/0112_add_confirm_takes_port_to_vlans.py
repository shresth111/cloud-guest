"""``confirm_takes_port`` on ``vlans``. One NOT NULL boolean, plus a
one-time backfill for rows that already took their port.

An access-mode VLAN takes a physical port untagged, pulling it out of
whatever bridge it was in. ``0111`` made that reversible by recording the
bridge, and the dashboard warns when the chosen port is a bridge member.
Neither refuses: the push still takes the port. This column is the consent
the push checks before it does.

A column and not a request flag, because the push is a separate request
from the one that chose the port -- ``POST /vlans/{pk}/push`` carries no
body, can be issued days later, and can be a retry by someone else. A flag
on create/update would not survive to be read; a flag on the push would ask
whoever pressed "retry", not whoever picked the port.

``server_default='false'`` and NOT NULL: every existing row gets a real
value, and the default is the safe one. False is what makes the refusal
happen -- a default of true would ship the column and change nothing.

## The backfill, and why it is not simply "false everywhere"

Rows with ``port_mode='access'`` that have already reached a device
(``device_pushed_at IS NOT NULL``) are set true.

Their port is already out of its bridge; this platform took it, under the
old behaviour, and the customer has been living with the result. Leaving
them false would mean the next push of a VLAN that has been working for
months fails with a 409 about a decision made long ago -- and re-pushing is
the recovery path when device state has drifted, so the refusal would land
exactly when the operator most needs the push to work. The acknowledgement
is meant to catch the decision *before* it is acted on; for these rows it
has already been acted on, and asking now protects nothing.

Everything else is false, and that is the interesting half:

* access rows that have never been pushed -- the decision is still ahead of
  them, which is the only moment the question does any good;
* access rows whose only push FAILED -- nothing was taken, so nothing is
  grandfathered;
* every trunk row -- a trunk never moves a port, so the flag never gates
  its push and false is simply the honest "was never asked". If such a row
  is later switched to access mode, ``VlanService.update_vlan`` would have
  cleared the flag anyway.

The backfill is a data statement about history, so ``downgrade`` only drops
the column: there is nothing to un-say.

Revision ID: 0112_add_confirm_takes_port_to_vlans
Revises: 0111_add_previous_bridge_to_vlans
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0112_add_confirm_takes_port_to_vlans"
down_revision = "0111_add_previous_bridge_to_vlans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vlans",
        sa.Column(
            "confirm_takes_port",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    # Grandfathers the rows whose port was already taken -- see the module
    # docstring. Scoped to access mode *and* an actual completed push, so a
    # row that merely intends to take a port is not credited with having
    # been asked.
    op.execute(
        "UPDATE vlans SET confirm_takes_port = true "
        "WHERE port_mode = 'access' AND device_pushed_at IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_column("vlans", "confirm_takes_port")

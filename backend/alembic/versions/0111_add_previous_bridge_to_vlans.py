"""``previous_bridge`` on ``vlans``. Additive-only, one nullable column.

An access-mode VLAN takes a physical port untagged, which means pulling it
out of whatever bridge it was in. Nothing recorded which bridge that was, so
``delete_vlan`` deliberately left the port unbridged rather than rejoin a
guessed one -- both halves of that reasoning were sound, and the outcome was
still that the product could take a port and not give it back.

It happened: a venue's access point was on a bridge port, an access VLAN
took it, the guest network stopped serving, and an engineer restored the
membership by hand because no code path could.

Nullable with no server_default, deliberately. There is no truthful
backfill: for every existing row this platform genuinely does not know what
the port's previous bridge was, and ``NULL`` says exactly that. It is also
the value that keeps the old behaviour for those rows -- the delete path
leaves the port unbridged when this is unset, which is what it did for all
of them before this column existed. A ``''`` or a guessed ``'bridge'`` would
turn "unknown" into a claim, and the delete path would act on it.

Only written for ``port_mode='access'``. A trunk VLAN never takes a port, so
it has no previous bridge and the column stays NULL for its whole life.

Revision ID: 0111_add_previous_bridge_to_vlans
Revises: 0110_add_device_push_columns_to_radius_nas_clients
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0111_add_previous_bridge_to_vlans"
down_revision = "0110_add_device_push_columns_to_radius_nas_clients"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vlans",
        sa.Column("previous_bridge", sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vlans", "previous_bridge")

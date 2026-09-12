"""Router-side push state on ``radius_nas_clients``. Additive-only, three
columns, one table.

A NAS registration has two halves and this table only recorded one of them.
``hub_client_synced_ip``/``hub_client_synced_at`` say the hub's FreeRADIUS
confirmed a ``client{}`` stanza. Nothing said whether the **router's** own
``/radius`` row and its ``/radius incoming`` CoA listener were ever
written -- and until now nothing could, because the gateway method that
writes them (``set_radius_client_config``) had no caller in this
application. The only writer that could run lived in the combined config
script, delivered over SSH, and a port sweep from the platform reached only
8728 on a fleet router.

Mirrors ``vlans``, ``dhcp_pools``, ``content_filter_rules``,
``port_forwarding_rules`` and ``guest_access_rules`` (0102, 0103, 0106,
0107, 0108) so every domain that reaches a device reads the same way in a
database session.

**``server_default='pending'``, unlike 0108, and that is deliberate.**
There, "as before" was not a single truthful value, so the columns were
left nullable. Here it is: no code path has ever pushed one of these rows
from this application, so ``pending`` -- "this path has not run" -- is true
of every existing row without exception. Note what it does *not* claim: a
router provisioned by pasting the generated setup script does carry a
``/radius`` row, one this platform never wrote and cannot account for.
``pending`` is a statement about this platform's own push, not about the
device being empty.

Revision ID: 0110_add_device_push_columns_to_radius_nas_clients
Revises: 0109_add_failover_push_columns_to_isp_links
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0110_add_device_push_columns_to_radius_nas_clients"
down_revision = "0109_add_failover_push_columns_to_isp_links"
branch_labels = None
depends_on = None

_TABLE = "radius_nas_clients"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        _TABLE, sa.Column("device_push_error", sa.Text(), nullable=True)
    )
    op.add_column(
        _TABLE,
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "device_pushed_at")
    op.drop_column(_TABLE, "device_push_error")
    op.drop_column(_TABLE, "device_push_status")

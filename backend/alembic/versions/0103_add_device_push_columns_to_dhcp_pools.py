"""Device-push tracking on ``dhcp_pools``. Additive-only, three columns.

Creating a DHCP pool wrote a row and returned 201. Nothing else happened.
``app.domains.dhcp.service``'s own module docstring said so plainly --
"No live device push in this pass ... this domain has no
``device_adapters.py`` and no Celery task" -- and deferred real
provisioning to a "not-yet-built Network Configuration Management
domain".

The writer was never the missing piece. ``wyfy_device_gateway
.mikrotik_adapter.configure_dhcp_pool`` already issued the three real
RouterOS operations (``/ip pool add``, ``/ip dhcp-server add``, ``/ip
dhcp-server network add``) over librouteros on port 8728, and had zero
callers anywhere in ``app/``. This is the same shape the VLAN domain was
in before 0102, and the consequence was worse: a VLAN with no DHCP hands
out no addresses, so a guest joining a "created" network gets nothing at
all.

These three columns mirror ``vlans``' own ``device_push_status``/
``device_push_error``/``device_pushed_at`` trio field-for-field (and
``qos_traffic_rules``' before it) so every domain that reaches a device
reads the same way in a database session.

**NOT NULL with a server_default, matching 0102's reasoning.** The value
meaning "as before" is a particular value, not an absence: every existing
pool row has demonstrably never been pushed, because no code path could
push one. ``pending`` states the truth for all of them and the backfill is
exactly the default. A nullable column would introduce a fourth
"unknown" state nothing in the domain means or handles.

``device_push_error`` is ``Text`` and holds the raw ``str(exc)``, shown to
the operator verbatim -- a RouterOS error ("already have such item", "no
such item", a policy denial) is more useful unedited than summarized.

**Reversibility.** ``downgrade`` drops all three. Lossless for behaviour:
without them the domain simply has no push record, which is the
pre-migration state. It discards the history of which pools reached a
device, the correct direction to lose data in for a rollback -- the
alternative, keeping a status column whose writer is gone, would leave
rows asserting ``active`` with nothing able to correct them.

Revision ID: 0103_add_device_push_columns_to_dhcp_pools
Revises: 0103_add_discount_amount_to_invoices
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "0103_add_device_push_columns_to_dhcp_pools"
down_revision = "0103_add_discount_amount_to_invoices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dhcp_pools",
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "dhcp_pools", sa.Column("device_push_error", sa.Text(), nullable=True)
    )
    op.add_column(
        "dhcp_pools",
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dhcp_pools", "device_pushed_at")
    op.drop_column("dhcp_pools", "device_push_error")
    op.drop_column("dhcp_pools", "device_push_status")

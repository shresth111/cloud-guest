"""WAN physical/routing interface split + PPPoE credentials on ``isp_links``.

Wave 1 Step 4: additive columns only. The legacy ``interface`` column is
retained for netwatch renderers and existing health-check code paths.

* ``physical_interface`` -- the real RouterOS port (e.g. ``ether1``).
* ``routing_interface`` -- the interface used for routing/NAT/health on
  this uplink (same as physical for static/DHCP; ``pppoe-wanN`` for PPPoE).
* ``pppoe_username`` -- plaintext, mirrors ``routers.api_username``.
* ``pppoe_password_encrypted`` -- Fernet via ``app.domains.router.crypto``.
* ``dns_override`` -- optional per-WAN DNS server list (JSONB).

Existing rows are backfilled: ``physical_interface`` and
``routing_interface`` are set from ``interface`` where present.

Revision ID: 0092_isp_links_physical_routing_split
Revises: 0091_create_router_snapshots_table
Create Date: 2026-08-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0092_isp_links_physical_routing_split"
down_revision = "0091_create_router_snapshots_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "isp_links",
        sa.Column("physical_interface", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "isp_links",
        sa.Column("routing_interface", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "isp_links",
        sa.Column("pppoe_username", sa.String(length=150), nullable=True),
    )
    op.add_column(
        "isp_links",
        sa.Column("pppoe_password_encrypted", sa.Text(), nullable=True),
    )
    op.add_column(
        "isp_links",
        sa.Column(
            "dns_override",
            postgresql.JSONB(),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE isp_links
        SET physical_interface = interface,
            routing_interface = interface
        WHERE interface IS NOT NULL
          AND physical_interface IS NULL
        """
    )


def downgrade() -> None:
    op.drop_column("isp_links", "dns_override")
    op.drop_column("isp_links", "pppoe_password_encrypted")
    op.drop_column("isp_links", "pppoe_username")
    op.drop_column("isp_links", "routing_interface")
    op.drop_column("isp_links", "physical_interface")

"""ISP Management: connection-mode-aware health checks (static/dhcp/pppoe).

Adds ``isp_links.connection_mode`` (``constants.IspConnectionMode``:
``static``/``dhcp``/``pppoe``) -- a real-world gap: a WAN link's gateway
IP is only ever a fixed, admin-known value for a *static* connection. A
DHCP-client link's gateway is assigned dynamically by the ISP and can
change at any time (resolved live from the router's own current dynamic
default route at health-check time -- see ``device_adapters
.get_dynamic_default_gateway``); a PPPoE link has no gateway-IP concept
at all (health is the PPPoE client interface's own up/down state -- see
``device_adapters.get_pppoe_interface_status``). This field drives which
of the three real health-check target-resolution strategies
``IspService.ping_link`` uses for a given link -- see that method's own
docstring.

Additive, ``NOT NULL`` with a server default of ``'static'`` so every
pre-existing row (all of which really did have a manually-entered
gateway IP before this field existed) backfills correctly with no
separate data migration.

Revision ID: 0072_add_isp_link_connection_mode
Revises: 0071_add_isp_link_manual_status_override
Create Date: 2026-08-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0072_add_isp_link_connection_mode"
down_revision = "0071_add_isp_link_manual_status_override"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "isp_links",
        sa.Column(
            "connection_mode",
            sa.String(length=20),
            nullable=False,
            server_default="static",
        ),
    )


def downgrade() -> None:
    op.drop_column("isp_links", "connection_mode")

"""Add port_mode and enable_hotspot to vlans, backing the simplified
create-VLAN UX: trunk/access port-mode selection, tag ID (already
existed as vlan_id), and a per-VLAN hotspot on/off toggle.

"access" mode is deliberately modeled as a dedicated physical port pulled
out of the shared LAN bridge (see app.domains.vlan.models.Vlan's own
docstring on port_mode) rather than bridge-wide vlan-filtering, so it
never risks the shared production bridge's already-live traffic.

Revision ID: 0066_add_port_mode_and_hotspot_to_vlans
Revises: 0065_add_logo_key_to_brandings
Create Date: 2026-07-30
"""

import sqlalchemy as sa

from alembic import op

revision = "0066_add_port_mode_and_hotspot_to_vlans"
down_revision = "0065_add_logo_key_to_brandings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vlans",
        sa.Column(
            "port_mode", sa.String(20), nullable=False, server_default="trunk"
        ),
    )
    op.add_column(
        "vlans",
        sa.Column(
            "enable_hotspot",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("vlans", "enable_hotspot")
    op.drop_column("vlans", "port_mode")

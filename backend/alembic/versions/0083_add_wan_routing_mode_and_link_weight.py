"""WAN routing mode + per-link load-balance weight.

Two additive columns, no data backfill beyond each column's own default --
see ``app.domains.isp.constants.WanRoutingMode``'s own docstring for the
full design write-up.

``routers`` gains one column:

* ``wan_routing_mode`` (``VARCHAR(20) NOT NULL DEFAULT 'load_balance'``) --
  how 2+ enabled ``isp_links`` rows are combined on-device by the
  generated RouterOS setup script. ``load_balance`` is the real, honest
  backfill for every existing router -- it is the *only* behavior this
  platform has ever generated for a multi-WAN router, so every
  pre-existing row keeps its actual current behavior unchanged.

``isp_links`` gains one column:

* ``load_balance_weight`` (``INTEGER``, nullable) -- a relative
  load-balance ratio, only meaningful when the owning router is in
  ``load_balance`` mode. ``NULL`` for every pre-existing row (and any
  link an admin hasn't explicitly weighted yet), meaning "this link
  splits evenly with every other enabled link" -- never a fabricated
  default weight.

Revision ID: 0083_add_wan_routing_mode_and_link_weight
Revises: 0082_create_quotations_tables
Create Date: 2026-08-16
"""

import sqlalchemy as sa

from alembic import op

revision = "0083_add_wan_routing_mode_and_link_weight"
down_revision = "0082_create_quotations_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "routers",
        sa.Column(
            "wan_routing_mode",
            sa.String(length=20),
            nullable=False,
            server_default="load_balance",
        ),
    )
    op.add_column(
        "isp_links",
        sa.Column("load_balance_weight", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("isp_links", "load_balance_weight")
    op.drop_column("routers", "wan_routing_mode")

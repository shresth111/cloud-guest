"""Provisioning Engine: adds ``vendor`` to ``routers`` and
``config_templates``.

Both columns are ``NOT NULL`` with ``server_default='mikrotik'`` and, unlike
``radius_nas_clients.nas_code`` (migration `0030`), **are** effectively
backfilled for every pre-existing row -- not via a separate ``UPDATE``
statement, but because Postgres applies a constant column default to every
existing row the moment the column is added (this is the fast, metadata-only
path Postgres has used for ``ADD COLUMN ... DEFAULT <constant> NOT NULL``
since version 11). This is safe specifically because the value is
unambiguous for every row that predates this migration: every ``Router``
deployed on this platform, and every ``ConfigTemplate`` ever authored for
one, targets MikroTik RouterOS today -- there is no per-row uncertainty the
way there was for ``nas_code`` (a value that had to be freshly generated per
row, not merely defaulted).

See ``app/domains/router_provisioning/adapters.py``'s own module docstring
and ``docs/router_provisioning/PROVISIONING_ENGINE.md`` for the full design
write-up behind this extension -- a Strategy/Adapter seam
(``ProvisioningAdapterProtocol``) other vendors plug into by implementing it
and registering one entry, with zero change to this module's existing
config-template/version/job-queue workflow.

Revision ID: 0031_add_vendor_to_router_and_template
Revises: 0030_extend_radius_nas_clients
Create Date: 2026-07-20
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0031_add_vendor_to_router_and_template"
down_revision = "0030_extend_radius_nas_clients"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "routers",
        sa.Column("vendor", sa.String(50), nullable=False, server_default="mikrotik"),
    )
    op.create_index("ix_routers_vendor", "routers", ["vendor"])

    op.add_column(
        "config_templates",
        sa.Column("vendor", sa.String(50), nullable=False, server_default="mikrotik"),
    )
    op.create_index("ix_config_templates_vendor", "config_templates", ["vendor"])


def downgrade() -> None:
    op.drop_index("ix_config_templates_vendor", table_name="config_templates")
    op.drop_column("config_templates", "vendor")

    op.drop_index("ix_routers_vendor", table_name="routers")
    op.drop_column("routers", "vendor")

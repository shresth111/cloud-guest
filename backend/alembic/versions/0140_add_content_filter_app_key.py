"""Content filtering: ``app_key`` on content filter rules.

Additive only. ``content_filter_rules`` gains a nullable ``app_key``: the
curated app (``app.domains.content_filtering.app_catalogue``) a row was
created for when a venue switched that app off from the "Apps" section of
Block Websites. ``NULL`` for every existing row and for every website a
customer blocks by hand, so nothing changes for any router until someone
uses the new toggle. It is what lets "unblock YouTube" remove exactly the
rows that toggle created and never a site the customer blocked themselves.

Nothing is written to any router.

Revision ID: 0140_add_content_filter_app_key
Revises: 0139_add_dns_bypass_layers
Create Date: 2026-10-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0140_add_content_filter_app_key"
down_revision = "0139_add_dns_bypass_layers"
branch_labels = None
depends_on = None

_TABLE = "content_filter_rules"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("app_key", sa.String(length=40), nullable=True))
    op.create_index("ix_content_filter_rules_app_key", _TABLE, ["app_key"])


def downgrade() -> None:
    op.drop_index("ix_content_filter_rules_app_key", table_name=_TABLE)
    op.drop_column(_TABLE, "app_key")

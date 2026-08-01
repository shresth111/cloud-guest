"""ISP Management: manual health-status override support.

Adds a ``source`` tag (``constants.HealthStatusSource``:
``automated``/``manual``) to both ``isp_links`` (its *current*
``health_status_source``) and ``isp_health_checks`` (each row's own
``source``) -- backs ``IspService.set_manual_health_status``, the
"Internet Connection" dashboard view's one real write (an admin's own
up/down override of a link's status; never a device push). Deliberately a
source tag on the *existing* healthy/degraded/unhealthy/unknown
vocabulary, never a second status enum -- see ``models.py``'s own
"Manual status override" write-up.

Both columns are additive, ``NOT NULL`` with a server default of
``'automated'`` so every pre-existing row (all of which really did come
from the real health-check sweep) backfills correctly with no separate
data migration.

Revision ID: 0071_add_isp_link_manual_status_override
Revises: 0070_add_email_to_guest_access_rules
Create Date: 2026-08-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0071_add_isp_link_manual_status_override"
down_revision = "0070_add_email_to_guest_access_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "isp_links",
        sa.Column(
            "health_status_source",
            sa.String(length=20),
            nullable=False,
            server_default="automated",
        ),
    )
    op.add_column(
        "isp_health_checks",
        sa.Column(
            "source",
            sa.String(length=20),
            nullable=False,
            server_default="automated",
        ),
    )


def downgrade() -> None:
    op.drop_column("isp_health_checks", "source")
    op.drop_column("isp_links", "health_status_source")

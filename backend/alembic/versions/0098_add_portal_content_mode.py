"""Captive Portal content modes: ``content_mode`` and its per-mode source
columns on ``captive_portal_configs``. Additive-only, one table.

Adds five columns backing ``constants.PortalContentMode`` -- what the
guest-facing portal presents as its primary content before/instead of the
sign-in form (frontend ``PortalContentBlock``):

* ``content_mode`` -- ``String(20) NOT NULL``, ``server_default 'login'``.
  The selector; one of ``login``/``image``/``text``/``redirect``/``survey``.
* ``content_heading`` -- ``String(200)``, nullable.
* ``content_body`` -- ``Text``, nullable.
* ``content_image_url`` -- ``String(500)``, nullable.
* ``content_survey`` -- ``JSONB``, nullable.

**Why the default is ``'login'``, and why that is not merely the safe
choice.** Exactly the reasoning 0090's ``powered_by_enabled DEFAULT true``
records: every row predating this migration is a venue that renders only
the sign-in card, and ``'login'`` is the ``PortalContentMode`` value that
means "unchanged from what this row already effectively was". Backfilling
every existing row to ``'login'`` is therefore a pure no-op on what any
guest currently sees -- the feature only ever changes a portal once an
admin deliberately picks a different mode. The four content columns are
nullable because a mode can be selected before its content is authored (a
draft), and the frontend degrades to the sign-in card when the chosen
mode's source column is empty; ``NULL`` there means "not yet filled in",
which is a real, distinct state (unlike ``content_mode`` itself, which
always has a meaningful value).

``redirect`` mode deliberately gets no new column -- it reuses the
pre-existing ``redirect_url`` (a portal's post-login destination), so the
two can never drift apart.

**Reversibility.** ``downgrade`` drops all five columns. Lossless for the
guest-facing render of every pre-migration venue (all of which were, and
return to being, sign-in-only); it discards any content-mode configuration
authored after this deploy, which is the correct direction to lose data
in for a rollback.

Revision ID: 0098_add_portal_content_mode
Revises: 0097_wireguard_peer_issuances_and_nas_hub_sync
Create Date: 2026-08-30
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0098_add_portal_content_mode"
down_revision = "0097_wireguard_peer_issuances_and_nas_hub_sync"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "content_mode",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'login'"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("content_heading", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("content_body", sa.Text(), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("content_image_url", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("content_survey", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "content_survey")
    op.drop_column("captive_portal_configs", "content_image_url")
    op.drop_column("captive_portal_configs", "content_body")
    op.drop_column("captive_portal_configs", "content_heading")
    op.drop_column("captive_portal_configs", "content_mode")

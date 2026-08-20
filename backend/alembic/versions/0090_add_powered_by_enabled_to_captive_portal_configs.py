"""Captive Portal v7 Part 3 (P4): ``powered_by_enabled`` on
``captive_portal_configs``. Additive-only, one column, one table.
See ``docs/captive-portal-v7-design-spec.md`` (``cloudguest-foundation``
repo) Part 3, item P4.

``powered_by_enabled`` -- ``Boolean NOT NULL``, ``server_default``
``true``.

Whether the guest-facing portal renders the "Powered by Wyfy Guest"
attribution (``PortalShell.tsx:400``, shipped as #84). Turning it **off**
is white-label behaviour and is gated on the ``white_label`` plan feature
by a service-layer check in ``CaptivePortalService.update_config``; this
migration only creates the storage.

**Why the default is ``true``, and why that is not merely the safe
choice.** Every row that predates this migration is a venue that has
always rendered the attribution, so ``true`` is the value meaning
"unchanged from what this row already effectively was" -- the same test
0088's ``'system'``/``55`` and 0089's ``50``/``25`` are chosen against,
and the reason those are NOT NULL with a server_default while 0089's
``brandings`` measurements are nullable. There is no "not yet decided"
state to encode here: a portal either shows the mark or it does not, and
before this column existed every portal showed it. A nullable column
would invent a third state the renderer has no meaning for.

It also means this migration cannot leak revenue on the way in. If the
default were ``false``, every existing venue -- including every venue
with no white-label entitlement -- would silently lose the attribution
the moment this deploys, which is precisely the leak P4 exists to close.

**Reversibility.** ``downgrade`` drops the column outright. That is
lossless for the guest-facing render, because dropping it returns every
portal to the pre-migration behaviour of unconditionally showing the
attribution -- the same state the column's own default encodes. It does
discard the stored choice of any tenant who had turned the mark off, and
that is the correct direction to lose data in: a rollback that silently
left attribution *off* for tenants whose entitlement can no longer be
checked would reopen the leak, whereas a rollback that turns it back on
costs an entitled tenant one click to restore.

Revision ID: 0090_add_powered_by_enabled_to_captive_portal_configs
Revises: 0089_add_background_image_metrics_and_focal_point
Create Date: 2026-08-20
"""

import sqlalchemy as sa

from alembic import op

revision = "0090_add_powered_by_enabled_to_captive_portal_configs"
down_revision = "0089_add_background_image_metrics_and_focal_point"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "powered_by_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "powered_by_enabled")

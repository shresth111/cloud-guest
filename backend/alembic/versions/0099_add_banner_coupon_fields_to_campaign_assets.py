"""Banner & Discount content on ``campaign_assets``: ``headline``,
``subtext``, ``coupon_code`` and ``coupon_expires_at``. Additive-only, one
table.

The Campaigns domain's ``BANNER`` type historically carried only a visual
asset (``image_url``/``click_url``/``alt_text``), so a banner could only ever
be a *picture* a guest taps -- there was nowhere to store the text-and-coupon
promotion the product's own "Banner & Discounts" campaign type describes
("Flat 20% off this weekend", "Show this coupon at checkout", code
``SAVE20``). These four nullable columns add exactly that, so a banner can be
authored as real, rendered copy plus a coupon a guest can read and use --
never a second image the venue must design in an external tool first.

* ``headline`` -- ``String(200)``, nullable. The promo headline, e.g.
  "Flat 20% off this weekend".
* ``subtext`` -- ``String(500)``, nullable. Supporting line, e.g. "Show this
  coupon at checkout".
* ``coupon_code`` -- ``String(60)``, nullable. The redeemable code, e.g.
  ``SAVE20`` -- rendered as a copyable chip by the guest-facing overlay.
* ``coupon_expires_at`` -- ``TIMESTAMPTZ``, nullable. Optional validity
  cutoff the frontend renders as "Valid until ...".

**All four nullable, and no backfill.** Every existing ``campaign_assets``
row is an image/redirect asset authored before this column existed; ``NULL``
across all four is the honest "this banner has no text/coupon content"
state, and the pre-existing ``validators.validate_asset_urls`` already
guarantees such a row still carries at least an ``image_url`` or
``click_url`` to be renderable. This is a pure addition: no guest sees any
change until a venue authors banner copy or a coupon.

**Reversibility.** ``downgrade`` drops all four columns. Lossless for every
pre-migration image/redirect banner (which never used them); it discards any
text/coupon banner content authored after this deploy, the correct direction
to lose data in for a rollback.

Revision ID: 0099_add_banner_coupon_fields_to_campaign_assets
Revises: 0098_add_portal_content_mode
Create Date: 2026-08-30
"""

import sqlalchemy as sa

from alembic import op

revision = "0099_add_banner_coupon_fields_to_campaign_assets"
down_revision = "0098_add_portal_content_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaign_assets",
        sa.Column("headline", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "campaign_assets",
        sa.Column("subtext", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "campaign_assets",
        sa.Column("coupon_code", sa.String(length=60), nullable=True),
    )
    op.add_column(
        "campaign_assets",
        sa.Column(
            "coupon_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("campaign_assets", "coupon_expires_at")
    op.drop_column("campaign_assets", "coupon_code")
    op.drop_column("campaign_assets", "subtext")
    op.drop_column("campaign_assets", "headline")

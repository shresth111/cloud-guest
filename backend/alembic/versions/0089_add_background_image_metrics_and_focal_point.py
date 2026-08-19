"""Captive Portal v7: background-image measurements + per-venue focal
point. Additive-only schema change to two existing tables, no new table.
See ``docs/captive-portal-v7-design-spec.md`` (``cloudguest-foundation``
repo) Part 4 and §1.4 C3/C4/C5 for the full design.

``brandings`` gains three columns, all ``Integer NULL``, all on a 0-100
scale, all computed once at upload by
``app.domains.branding.service._process_background_image`` and never
edited by hand:

* ``background_luminance`` -- mean luma of the uploaded background image.
* ``background_top_luminance`` -- mean luma of its top band, the zone the
  portal headline sits over.
* ``background_entropy`` -- normalized histogram entropy, the "busyness"
  measure §1.4 C5's refusal rule reads.

**Why these three are nullable, where every other column this pair of
migrations adds is NOT NULL with a server_default.** It is not laziness
about a backfill, and the difference is deliberate. A ``server_default``
is only honest when there is a value that means "unchanged from what this
row already effectively was" -- that is exactly what 0088's ``'system'``
and ``55`` are, and what 50/25 below are. There is no such value here.
Every ``brandings`` row that predates this migration holds an image
nobody has measured, and no number can stand in for a measurement that
was never taken: 0 is a real, legitimate reading (a pure black photo),
and a NOT NULL DEFAULT 0 would make "we have not looked at this image"
indistinguishable from "we looked, and it is black". The frontend
genuinely needs to tell those apart -- with a measurement it may use
*less* scrim than the §1.3 floor, and without one it must fall back to
that unconditional floor, which is AA-compliant over any image
whatsoever. NULL is the accurate encoding of "not measured", and it is
the state ``scripts/backfill_background_images.py`` clears one
organization at a time. Nothing is broken while a row is still NULL;
this is why no backfill is required for correctness, only for quality.

``captive_portal_configs`` gains two columns, both ``Integer NOT NULL``:

* ``background_focal_x`` -- ``server_default`` ``'50'``
* ``background_focal_y`` -- ``server_default`` ``'25'``

Integer percentages of the background image's own width/height (§1.4 C4).
The two defaults are not a taste judgement: together they are precisely
the frontend's current hardcoded ``background-position: center 25%``, so
this migration renders byte-identically for every venue that already
exists -- the same discipline 0088's ``background_overlay_strength``
default of 55 follows. Per-venue on ``captive_portal_configs`` rather
than org-level on ``brandings`` because the *same* shared organization
photo should crop differently at different venues; the three measurements
above are on ``brandings`` for the mirror-image reason, since they
describe the file rather than the venue.

Mirrors ``0088_add_guest_font_choice_and_overlay_strength``'s shape
one-for-one for the ``captive_portal_configs`` half.

Revision ID: 0089_add_background_image_metrics_and_focal_point
Revises: 0088_add_guest_font_choice_and_overlay_strength
Create Date: 2026-08-19
"""

import sqlalchemy as sa

from alembic import op

revision = "0089_add_background_image_metrics_and_focal_point"
down_revision = "0088_add_guest_font_choice_and_overlay_strength"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "brandings",
        sa.Column("background_luminance", sa.Integer(), nullable=True),
    )
    op.add_column(
        "brandings",
        sa.Column("background_top_luminance", sa.Integer(), nullable=True),
    )
    op.add_column(
        "brandings",
        sa.Column("background_entropy", sa.Integer(), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "background_focal_x",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("50"),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "background_focal_y",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("25"),
        ),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "background_focal_y")
    op.drop_column("captive_portal_configs", "background_focal_x")
    op.drop_column("brandings", "background_entropy")
    op.drop_column("brandings", "background_top_luminance")
    op.drop_column("brandings", "background_luminance")

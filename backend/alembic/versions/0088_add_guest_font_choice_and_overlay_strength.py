"""Captive Portal v6: guest heading-font choice + background overlay
strength. Additive-only schema change to one existing table, no new table.
See ``docs/captive-portal-v6-design-spec.md`` (``cloudguest-foundation``
repo) §3/§4/§6.1 for the full design.

``captive_portal_configs`` gains two columns:

* ``guest_font_choice`` -- a curated 4-value heading-font allowlist
  (``system`` / ``modern-sans`` / ``editorial-serif`` / ``bold-display``,
  see ``app.domains.captive_portal.constants.GuestFontChoice``). A plain
  ``String``, not a native Postgres enum type, for the same "additive
  member never needs an ALTER TYPE" reasoning ``theme`` already
  established (see ``constants.py``'s module docstring). ``NOT NULL`` with
  a ``server_default`` of ``'system'`` so every existing row keeps its
  previous, equivalent behavior -- the frontend's own safe default,
  rendering exactly as it does today.
* ``background_overlay_strength`` -- the guest-facing scrim's peak
  opacity as an integer percentage, 0-100. ``NOT NULL`` with a
  ``server_default`` of ``'55'`` -- chosen specifically because it
  reproduces the frontend's current hardcoded 0.55 peak-opacity scrim
  exactly (spec §4.2/§4.3), so no existing venue's rendered portal changes
  as a result of this migration.

Mirrors ``0085_add_portal_pin_login``/``0074_add_otp_whatsapp_enabled_to_
captive_portal_configs``'s identical shape one-for-one: a new, per-config
opt-in/tunable column, ``NOT NULL`` with a ``server_default`` so this is a
genuinely zero-behavior-change migration for every row that already
exists.

Revision ID: 0087_add_guest_font_choice_and_overlay_strength
Revises: 0086_create_channel_partners_table
Create Date: 2026-08-19
"""

import sqlalchemy as sa

from alembic import op

revision = "0088_add_guest_font_choice_and_overlay_strength"
down_revision = "0087_add_lead_qualification_fields_to_demo_requests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "guest_font_choice",
            sa.String(20),
            nullable=False,
            server_default="system",
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "background_overlay_strength",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("55"),
        ),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "background_overlay_strength")
    op.drop_column("captive_portal_configs", "guest_font_choice")

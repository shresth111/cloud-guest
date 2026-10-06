"""Merge the Device Logs revision into staging's chain. No-op.

``0150_create_device_logs_tables`` was built to ship to ``main`` on its own,
ahead of the staging promotion, so it chains on main's head
(``0143_add_require_guest_name_to_captive_portal_configs``). Staging already
contains that revision and continues past it (0148 merged it, 0149 follows),
so on staging 0150 is a second head and ``alembic upgrade head`` would
refuse to run (``tests/unit/test_migrations.py``). This revision only joins
the two; the same shape as ``0148_merge_main_require_guest_name``.

Promotion: ``main`` will already hold 0150 byte-for-byte (same commit, merged
into this branch rather than cherry-picked), and this merge revision arrives
with staging -- one head, nothing re-applied. Whichever of 0149 or 0150 an
environment is at, upgrading applies the other first, then this.

Revision ID: 0151_merge_device_logs_into_staging
Revises: 0149_add_require_guest_email_and_post_login_sequence,
    0150_create_device_logs_tables
Create Date: 2026-10-06
"""

from __future__ import annotations

revision = "0151_merge_device_logs_into_staging"
down_revision = (
    "0149_add_require_guest_email_and_post_login_sequence",
    "0150_create_device_logs_tables",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

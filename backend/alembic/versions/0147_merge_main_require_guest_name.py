"""Merge the two 0143 branches: main's ``require_guest_name`` (#353) and
staging's 0143-0146 chain (SSID tiers, speed gateways, Aruba APs, NAS
activity).

``main`` and ``staging`` both chained a 0143 off
``0142_create_instant_on_poller_tables``. Merging main into a branch based
on staging therefore produces two heads, which makes
``alembic upgrade head`` refuse to run (see
``tests/unit/test_migrations.py``). This revision does nothing but join
them; whichever side is upgraded first, the other's columns are applied
before this one.

Revision ID: 0147_merge_main_require_guest_name
Revises: 0143_add_require_guest_name_to_captive_portal_configs,
    0146_add_radius_nas_last_activity
Create Date: 2026-10-06
"""

from __future__ import annotations

revision = "0147_merge_main_require_guest_name"
down_revision = (
    "0143_add_require_guest_name_to_captive_portal_configs",
    "0146_add_radius_nas_last_activity",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

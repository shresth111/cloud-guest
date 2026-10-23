"""integ/isp-test ONLY: merge PARITY-2's 0177 with the integ merge head.

``0177_isp_parity_settings`` (PARITY-2 F1-F3, #447) revises
``0176_isp_addon_allowances``; integ already carries
``0177_merge_integ_tr069_location_and_addons``. This merge revision exists only
on the integration branch so ``alembic upgrade head`` has one head. Do not
merge it to main.

Revision ID: 0178_merge_integ_parity_settings
Revises: 0177_merge_integ_tr069_location_and_addons, 0177_isp_parity_settings
Create Date: 2026-10-23
"""

from __future__ import annotations

revision = "0178_merge_integ_parity_settings"
down_revision = (
    "0177_merge_integ_tr069_location_and_addons",
    "0177_isp_parity_settings",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

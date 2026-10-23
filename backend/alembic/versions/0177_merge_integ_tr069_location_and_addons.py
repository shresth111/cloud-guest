"""integ/isp-test ONLY: merge the two 0176 heads.

``0176_tr069_location_credentials`` (#444) and ``0176_isp_addon_allowances``
(B6 add-ons) both revise 0175 on separate PR branches. This merge revision
exists only on the integration branch so the test box can run
``alembic upgrade head``. When the stack lands on main, the second PR to land
should re-point its down_revision instead, and this file must not be merged.

Revision ID: 0177_merge_integ_tr069_location_and_addons
Revises: 0176_tr069_location_credentials, 0176_isp_addon_allowances
Create Date: 2026-10-23
"""

from __future__ import annotations

revision = "0177_merge_integ_tr069_location_and_addons"
down_revision = ("0176_tr069_location_credentials", "0176_isp_addon_allowances")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

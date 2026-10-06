"""Join main's SNMP copy (0143a) into the staging chain.

SNMP shipped to prod from main as ``0143a_add_router_snmp_v3_and_poll_status``
(parented on main's 0143) ahead of the rest of staging. Staging carries the
same columns as ``0150``. Both revisions are idempotent, so this merge only
joins the two heads; whichever ran first did the work.

Revision ID: 0151_merge_snmp_main_copy
Revises: 0150_add_router_snmp_v3_and_poll_status,
    0143a_add_router_snmp_v3_and_poll_status
Create Date: 2026-10-06
"""

from __future__ import annotations

revision = "0151_merge_snmp_main_copy"
down_revision = (
    "0150_add_router_snmp_v3_and_poll_status",
    "0143a_add_router_snmp_v3_and_poll_status",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

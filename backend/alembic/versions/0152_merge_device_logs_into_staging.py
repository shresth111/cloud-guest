"""Merge the Device Logs revision into staging's chain. No-op.

``0150_create_device_logs_tables`` was built to ship to ``main`` on its own,
ahead of the staging promotion, so it chains on main's head
(``0143a_add_router_snmp_v3_and_poll_status``, SNMP #371). Staging carries
that revision too and continues past it (``0151_merge_snmp_main_copy``), so
on staging 0150 is a second head and ``alembic upgrade head`` would refuse
to run (``tests/unit/test_migrations.py``, and CI's "exactly one head" step).
This revision only joins the two -- the same shape as
``0148_merge_main_require_guest_name`` and ``0151_merge_snmp_main_copy``.

The revision id ``0150_create_device_logs_tables`` is distinct from
staging's ``0150_add_router_snmp_v3_and_poll_status``; only the numeric file
prefix coincides.

Promotion: ``main`` will already hold 0150 byte-for-byte (same commit, merged
into this branch rather than cherry-picked), and this merge revision arrives
with staging -- one head, nothing re-applied. Whichever side an environment
is on, upgrading applies the other first, then this.

Revision ID: 0152_merge_device_logs_into_staging
Revises: 0151_merge_snmp_main_copy, 0150_create_device_logs_tables
Create Date: 2026-10-06
"""

from __future__ import annotations

revision = "0152_merge_device_logs_into_staging"
down_revision = (
    "0151_merge_snmp_main_copy",
    "0150_create_device_logs_tables",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

"""Merge the guest device events revision into staging's chain. No-op.

``0154_create_guest_device_events`` was built to ship to ``main`` on its own,
so it chains on main's head, ``0150_create_device_logs_tables``. Staging
carries 0150 too and continues past it (0152 merge, 0153 NetFlow), so on
staging 0154 is a second head and ``alembic upgrade head`` would refuse to
run. This revision only joins the two -- the same shape as
``0152_merge_device_logs_into_staging``.

Promotion: ``main`` will already hold 0154 byte-for-byte (merged into this
branch, not cherry-picked), and this merge revision arrives with staging --
one head, nothing re-applied.

Revision ID: 0155_merge_guest_device_events_into_staging
Revises: 0153_create_traffic_flow_windows, 0154_create_guest_device_events
Create Date: 2026-10-07
"""

from __future__ import annotations

revision = "0155_merge_guest_device_events_into_staging"
down_revision = (
    "0153_create_traffic_flow_windows",
    "0154_create_guest_device_events",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

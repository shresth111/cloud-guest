"""Device Logs: per-router firewall logging switch on ``router_remote_logging``.

Four columns:

* ``firewall_logging_enabled`` -- a Master turned firewall logging on for
  this router (rate-limited ``WYFY-FW`` log rows above Wyfy's own forward
  drops). NOT NULL, default false: every existing router stays off.
* ``firewall_logging_verified_at`` / ``_verified_ok`` / ``_detail`` -- the
  last read-back of those rows from the device.

Adding a column with a constant default is metadata-only on Postgres 11+,
so no table rewrite; the table holds one row per configured router anyway.
Idempotent (``IF NOT EXISTS``).

Revision ID: 0168_router_remote_logging_firewall_logging
Revises: 0167_partition_device_log_events
Create Date: 2026-10-18
"""

from __future__ import annotations

from alembic import op

revision = "0168_router_remote_logging_firewall_logging"
down_revision = "0167_partition_device_log_events"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("firewall_logging_enabled", "BOOLEAN NOT NULL DEFAULT false"),
    ("firewall_logging_verified_at", "TIMESTAMPTZ NULL"),
    ("firewall_logging_verified_ok", "BOOLEAN NULL"),
    ("firewall_logging_detail", "TEXT NULL"),
)


def upgrade() -> None:
    for name, ddl in _COLUMNS:
        op.execute(
            f"ALTER TABLE router_remote_logging ADD COLUMN IF NOT EXISTS {name} {ddl}"
        )


def downgrade() -> None:
    for name, _ in reversed(_COLUMNS):
        op.execute(f"ALTER TABLE router_remote_logging DROP COLUMN IF EXISTS {name}")

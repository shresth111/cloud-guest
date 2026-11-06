"""Traffic flow records: merged rows, and counters for what was not stored.

Additive only. Idempotent (``IF NOT EXISTS`` throughout).

* ``traffic_flow_records`` gains ``records_merged`` (how many collector
  records a row stands for; 1 for every row written before this) and
  ``ports_merged`` (the venue-side port differed between them and is NULL).
* ``traffic_flow_record_caps`` gains ``rows_received``, ``rows_merged`` and
  ``rows_internal``, so a reader can say how many records were merged and
  how many were not stored, by reason. 0 for days before this revision:
  those days were not counted, which is not the same as none.

Every addition is NOT NULL with a default, so it is safe on a table that
already has rows.

Revision ID: 0163_traffic_flow_record_merge
Revises: 0162_traffic_flow_records
Create Date: 2026-10-13
"""

from __future__ import annotations

from alembic import op

revision = "0163_traffic_flow_record_merge"
down_revision = "0162_traffic_flow_records"
branch_labels = None
depends_on = None

_ADDITIONS = (
    ("traffic_flow_records", "records_merged", "INTEGER NOT NULL DEFAULT 1"),
    ("traffic_flow_records", "ports_merged", "BOOLEAN NOT NULL DEFAULT false"),
    ("traffic_flow_record_caps", "rows_received", "BIGINT NOT NULL DEFAULT 0"),
    ("traffic_flow_record_caps", "rows_merged", "BIGINT NOT NULL DEFAULT 0"),
    ("traffic_flow_record_caps", "rows_internal", "BIGINT NOT NULL DEFAULT 0"),
)


def upgrade() -> None:
    for table, column, definition in _ADDITIONS:
        op.execute(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}"
        )


def downgrade() -> None:
    for table, column, _definition in reversed(_ADDITIONS):
        op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {column}")

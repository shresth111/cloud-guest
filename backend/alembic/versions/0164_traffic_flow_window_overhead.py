"""Traffic flow: platform overhead on the window.

Adds ``bytes_overhead_up`` and ``bytes_overhead_down`` to
``traffic_flow_windows``: the router's own traffic to the platform (its
management tunnel and what rides inside it), which is now classified at
ingest and kept out of client traffic.

Nullable, with NO default and NO backfill, on purpose. A window stored
before this revision has its overhead still inside its client and internal
figures; NULL says "not classified" and lets the reads correct those windows
from the destination buckets instead of trusting a zero.

Adding a nullable column without a default is a catalogue-only change in
PostgreSQL (no table rewrite). Idempotent (``IF NOT EXISTS``), like 0156 to
0163.

Revision ID: 0164_traffic_flow_window_overhead
Revises: 0163_traffic_flow_record_merge
Create Date: 2026-10-13
"""

from __future__ import annotations

from alembic import op

revision = "0164_traffic_flow_window_overhead"
down_revision = "0163_traffic_flow_record_merge"
branch_labels = None
depends_on = None

COLUMNS = ("bytes_overhead_up", "bytes_overhead_down")


def upgrade() -> None:
    for column in COLUMNS:
        op.execute(
            "ALTER TABLE traffic_flow_windows "
            f"ADD COLUMN IF NOT EXISTS {column} BIGINT NULL"
        )


def downgrade() -> None:
    for column in COLUMNS:
        op.execute(f"ALTER TABLE traffic_flow_windows DROP COLUMN IF EXISTS {column}")

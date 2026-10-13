"""Traffic flow: packets on the destination and service buckets.

Adds ``packets_up`` and ``packets_down`` to ``traffic_flow_dest_buckets``
and ``traffic_flow_service_buckets``.

Nullable, with NO default and NO backfill, on purpose: rows written before
this revision were stored without a packet count, and that is "not
measured", which must stay distinct from zero packets. They keep NULL for
the rest of their 7-day life; the API returns ``null`` for them. New rows
get a number from the collector.

Adding a nullable column without a default is a catalogue-only change in
PostgreSQL (no table rewrite), so this is safe on the live tables.

Idempotent (``IF NOT EXISTS`` throughout), like 0156 to 0160.

Revision ID: 0161_traffic_flow_bucket_packets
Revises: 0160_traffic_flow_country_buckets
Create Date: 2026-10-13
"""

from __future__ import annotations

from alembic import op

revision = "0161_traffic_flow_bucket_packets"
down_revision = "0160_traffic_flow_country_buckets"
branch_labels = None
depends_on = None

TABLES = ("traffic_flow_dest_buckets", "traffic_flow_service_buckets")
COLUMNS = ("packets_up", "packets_down")


def upgrade() -> None:
    for table in TABLES:
        for column in COLUMNS:
            op.execute(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} BIGINT NULL"
            )


def downgrade() -> None:
    for table in TABLES:
        for column in COLUMNS:
            op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {column}")

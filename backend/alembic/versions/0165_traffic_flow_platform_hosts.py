"""Traffic flow: resolved hub hostnames on the ingest-state row.

Adds ``platform_hosts`` to ``traffic_flow_ingest_state``: what the pull sweep
last resolved each hub hostname to, with the time and any error. Every
process reads it from here, so recognising a router's own tunnel to the
platform never needs a DNS lookup on a request.

``NOT NULL DEFAULT '{}'``: "nothing resolved yet" is an empty object, and the
single existing row gets it. Idempotent (``IF NOT EXISTS``).

Revision ID: 0165_traffic_flow_platform_hosts
Revises: 0164_traffic_flow_window_overhead
Create Date: 2026-10-13
"""

from __future__ import annotations

from alembic import op

revision = "0165_traffic_flow_platform_hosts"
down_revision = "0164_traffic_flow_window_overhead"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE traffic_flow_ingest_state "
        "ADD COLUMN IF NOT EXISTS platform_hosts JSONB NOT NULL DEFAULT '{}'::jsonb"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE traffic_flow_ingest_state DROP COLUMN IF EXISTS platform_hosts"
    )

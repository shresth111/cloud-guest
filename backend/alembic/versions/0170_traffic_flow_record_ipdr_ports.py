"""Traffic flow records for the IPDR: kept ports per router, NAT events.

Additive only. Idempotent (``IF NOT EXISTS`` throughout).

* ``router_traffic_flow_export.ipdr_ports`` (default false): the Master
  switch that makes a router's flow records keep the venue-side port, so
  its IPDR rows have Source Port and Translated Port.
* ``traffic_flow_records.nat_event`` (NULL for every existing row): an
  IPFIX NAT event row (conntrack create/delete) instead of a traffic
  record; the IANA natEvent value, 0 when the type was not sent.

Revision ID: 0170_traffic_flow_record_ipdr_ports
Revises: 0169_create_ipdr_tables
Create Date: 2026-10-19
"""

from __future__ import annotations

from alembic import op

revision = "0170_traffic_flow_record_ipdr_ports"
down_revision = "0169_create_ipdr_tables"
branch_labels = None
depends_on = None

_ADDITIONS = (
    ("router_traffic_flow_export", "ipdr_ports", "BOOLEAN NOT NULL DEFAULT false"),
    ("traffic_flow_records", "nat_event", "SMALLINT"),
)


def upgrade() -> None:
    for table, column, definition in _ADDITIONS:
        op.execute(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}"
        )


def downgrade() -> None:
    for table, column, _definition in reversed(_ADDITIONS):
        op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {column}")

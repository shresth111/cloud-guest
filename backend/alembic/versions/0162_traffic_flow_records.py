"""Traffic flow: per-flow records for the Master flow table, and their cap.

Additive only. Nothing writes to either table unless
``CLOUDGUEST_TRAFFIC_FLOW_ENABLED`` and
``CLOUDGUEST_TRAFFIC_FLOW_RECORDS_ENABLED`` are both true (both default
false) and the router's own export switch is on.

* ``traffic_flow_records`` -- one row per flow record of a router inside a
  5-minute collector window. Unlike the domain's other tables, a row puts a
  device beside the address it reached: read ``flow_records.py`` before
  adding a reader. Nullable columns are "the collector did not record it".
  Plain table, bigint identity, bounded DELETE at the retention setting.
  Not a CERT-In table; safe to prune.
* ``traffic_flow_record_caps`` -- per router and UTC day: rows stored, and
  since when the daily cap stopped storage.

Idempotent (``IF NOT EXISTS`` throughout), like its neighbours.

Chained on 0161 (bucket packets), the head of ``main`` when this was
opened. If another revision lands on 0161 first, repoint this one, or the
graph has two heads.

Revision ID: 0162_traffic_flow_records
Revises: 0161_traffic_flow_bucket_packets
Create Date: 2026-10-13
"""

from __future__ import annotations

from alembic import op

revision = "0162_traffic_flow_records"
down_revision = "0161_traffic_flow_bucket_packets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_records (
            id BIGINT GENERATED ALWAYS AS IDENTITY,
            router_id UUID NOT NULL,
            organization_id UUID NULL,
            location_id UUID NULL,
            source VARCHAR(32) NOT NULL,
            window_start TIMESTAMPTZ NOT NULL,
            window_seconds INTEGER NOT NULL,
            flow_start TIMESTAMPTZ NULL,
            flow_end TIMESTAMPTZ NULL,
            arrived_at TIMESTAMPTZ NULL,
            src_address INET NOT NULL,
            src_port INTEGER NULL,
            dst_address INET NOT NULL,
            dst_port INTEGER NULL,
            protocol SMALLINT NULL,
            nat_src_address INET NULL,
            nat_src_port INTEGER NULL,
            nat_dst_address INET NULL,
            nat_dst_port INTEGER NULL,
            bytes BIGINT NOT NULL DEFAULT 0,
            packets BIGINT NULL,
            flows BIGINT NULL,
            direction VARCHAR(16) NOT NULL,
            exporter_address VARCHAR(45) NOT NULL,
            exporter_port INTEGER NULL,
            CONSTRAINT pk_traffic_flow_records PRIMARY KEY (id),
            CONSTRAINT fk_traffic_flow_records_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT fk_traffic_flow_records_organization_id_organizations
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
                ON DELETE SET NULL,
            CONSTRAINT fk_traffic_flow_records_location_id_locations
                FOREIGN KEY (location_id) REFERENCES locations (id)
                ON DELETE SET NULL
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_records_window_start "
        "ON traffic_flow_records (window_start)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_records_router_window "
        "ON traffic_flow_records (router_id, window_start)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_records_location_window "
        "ON traffic_flow_records (location_id, window_start)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_record_caps (
            id BIGINT GENERATED ALWAYS AS IDENTITY,
            router_id UUID NOT NULL,
            location_id UUID NULL,
            day DATE NOT NULL,
            rows_stored BIGINT NOT NULL DEFAULT 0,
            capped_at TIMESTAMPTZ NULL,
            rows_not_stored BIGINT NOT NULL DEFAULT 0,
            CONSTRAINT pk_traffic_flow_record_caps PRIMARY KEY (id),
            CONSTRAINT fk_traffic_flow_record_caps_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT fk_traffic_flow_record_caps_location_id_locations
                FOREIGN KEY (location_id) REFERENCES locations (id)
                ON DELETE SET NULL,
            CONSTRAINT uq_traffic_flow_record_caps_key UNIQUE (router_id, day)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_record_caps_day "
        "ON traffic_flow_record_caps (day)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS traffic_flow_record_caps")
    op.execute("DROP TABLE IF EXISTS traffic_flow_records")

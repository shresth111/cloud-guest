"""Traffic flow (NetFlow/IPFIX MVP): ``traffic_flow_windows`` and
``traffic_flow_ingest_state``.

Purely additive: two new tables, no change to any existing row. Nothing
writes to them unless ``CLOUDGUEST_TRAFFIC_FLOW_ENABLED`` is true (default
off). See ``app.domains.traffic_flow``.

``traffic_flow_windows`` -- one row per (router, source, 5-minute window),
unique on exactly that so a re-pulled window is ON CONFLICT DO NOTHING.
Indexed on ``window_start`` for the overview and the 7-day retention delete.

``traffic_flow_ingest_state`` -- single row (id = 1): the pull cursor and the
last pull's outcome.

## Why this is 0156 and idempotent

The same two tables already exist on the staging database, created there by
staging's own ``0153_create_traffic_flow_windows``, which chains on a
staging-only merge revision and therefore cannot be brought to ``main`` as
it is. This revision chains on main's head instead and uses ``IF NOT
EXISTS`` throughout (the ``0154`` shape), with the same table, column and
constraint names as 0153, so:

* on a database that never had the tables (production) it creates them;
* on a database that already has them (staging) it does nothing.

Staging keeps its 0153 and needs one no-op merge revision joining its head
with this one when ``main`` is next merged into it (the same shape as
``0155_merge_guest_device_events_into_staging``). That revision is NOT part
of this change.

``downgrade`` drops the tables. Do not downgrade past this on staging
without also handling 0153.

Revision ID: 0156_create_traffic_flow_tables
Revises: 0154_create_guest_device_events
Create Date: 2026-10-12
"""

from __future__ import annotations

from alembic import op

revision = "0156_create_traffic_flow_tables"
down_revision = "0154_create_guest_device_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_windows (
            id UUID NOT NULL,
            router_id UUID NOT NULL,
            organization_id UUID NULL,
            location_id UUID NULL,
            source VARCHAR(32) NOT NULL,
            window_start TIMESTAMPTZ NOT NULL,
            window_seconds INTEGER NOT NULL,
            exporter_address VARCHAR(45) NOT NULL,
            bytes_total BIGINT NOT NULL,
            packets_total BIGINT NOT NULL,
            flows_total BIGINT NOT NULL,
            bytes_internal BIGINT NOT NULL,
            bytes_unclassified BIGINT NOT NULL,
            bytes_other_talkers BIGINT NOT NULL,
            bytes_other_destinations BIGINT NOT NULL,
            talker_count INTEGER NOT NULL,
            destination_count INTEGER NOT NULL,
            top_talkers JSONB NOT NULL,
            top_destinations JSONB NOT NULL,
            received_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT pk_traffic_flow_windows PRIMARY KEY (id),
            CONSTRAINT fk_traffic_flow_windows_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT fk_traffic_flow_windows_organization_id_organizations
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
                ON DELETE SET NULL,
            CONSTRAINT fk_traffic_flow_windows_location_id_locations
                FOREIGN KEY (location_id) REFERENCES locations (id)
                ON DELETE SET NULL,
            CONSTRAINT uq_traffic_flow_windows_router_window
                UNIQUE (router_id, source, window_start)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_windows_window_start "
        "ON traffic_flow_windows (window_start)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_ingest_state (
            id SMALLINT NOT NULL,
            last_window_start TIMESTAMPTZ NULL,
            last_pull_at TIMESTAMPTZ NULL,
            last_pull_ok BOOLEAN NULL,
            last_error TEXT NULL,
            unknown_exporters JSONB NOT NULL DEFAULT '[]'::jsonb,
            CONSTRAINT pk_traffic_flow_ingest_state PRIMARY KEY (id)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS traffic_flow_ingest_state")
    op.execute("DROP TABLE IF EXISTS traffic_flow_windows")

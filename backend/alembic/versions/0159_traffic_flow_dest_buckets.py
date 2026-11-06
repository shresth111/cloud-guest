"""Traffic flow: destination buckets (outside address by service, per window).

Additive only. Nothing writes to it unless ``CLOUDGUEST_TRAFFIC_FLOW_ENABLED``
is true (default off).

``traffic_flow_dest_buckets`` -- one row per (router, source,
5-minute window, outside address, protocol, outside port); see the model.
Venue-level: there is no device, MAC, guest or session column, and none is
to be added here. Plain table, bigint identity, the same 7-day bounded
DELETE as ``traffic_flow_service_buckets``. Not a CERT-In table; safe to
prune.

Idempotent (``IF NOT EXISTS`` throughout), like 0156 and 0157.

Numbered 0159 because a sibling branch (country buckets) has 0158. Both
were cut from 0157: whichever merges second must repoint its
``down_revision`` at the other, or the graph has two heads.

Revision ID: 0159_traffic_flow_dest_buckets
Revises: 0157_traffic_flow_services_export
Create Date: 2026-10-12
"""

from __future__ import annotations

from alembic import op

revision = "0159_traffic_flow_dest_buckets"
down_revision = "0157_traffic_flow_services_export"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_dest_buckets (
            id BIGINT GENERATED ALWAYS AS IDENTITY,
            router_id UUID NOT NULL,
            organization_id UUID NULL,
            location_id UUID NULL,
            source VARCHAR(32) NOT NULL,
            window_start TIMESTAMPTZ NOT NULL,
            window_seconds INTEGER NOT NULL,
            remote_address INET NOT NULL,
            protocol SMALLINT NOT NULL,
            remote_port INTEGER NOT NULL,
            bytes_up BIGINT NOT NULL DEFAULT 0,
            bytes_down BIGINT NOT NULL DEFAULT 0,
            flows BIGINT NOT NULL DEFAULT 0,
            CONSTRAINT pk_traffic_flow_dest_buckets PRIMARY KEY (id),
            CONSTRAINT fk_traffic_flow_dest_buckets_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT fk_traffic_flow_dest_buckets_organization_id_organizations
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
                ON DELETE SET NULL,
            CONSTRAINT fk_traffic_flow_dest_buckets_location_id_locations
                FOREIGN KEY (location_id) REFERENCES locations (id)
                ON DELETE SET NULL,
            CONSTRAINT uq_traffic_flow_dest_buckets_key
                UNIQUE (router_id, source, window_start, remote_address,
                        protocol, remote_port)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_dest_buckets_window_start "
        "ON traffic_flow_dest_buckets (window_start)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS "
        "ix_traffic_flow_dest_buckets_location_window "
        "ON traffic_flow_dest_buckets (location_id, window_start)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS traffic_flow_dest_buckets")

"""Traffic flow: country buckets (Geo Location).

Additive only. ``traffic_flow_country_buckets`` -- one row per (router,
source, 5-minute window, country, network); see the model and
``app/domains/traffic_flow/geo.py``. Plain table, bigint identity, the same
shape and the same bounded 7-day delete as ``traffic_flow_service_buckets``.

Nothing writes to it unless ``CLOUDGUEST_TRAFFIC_FLOW_ENABLED`` is true AND
the geo data files are present in the image.

Idempotent (``IF NOT EXISTS`` throughout), like 0156 and 0157. Not a CERT-In
table; safe to prune.

Revision ID: 0158_traffic_flow_country_buckets
Revises: 0157_traffic_flow_services_export
Create Date: 2026-10-12
"""

from __future__ import annotations

from alembic import op

revision = "0158_traffic_flow_country_buckets"
down_revision = "0157_traffic_flow_services_export"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_country_buckets (
            id BIGINT GENERATED ALWAYS AS IDENTITY,
            router_id UUID NOT NULL,
            organization_id UUID NULL,
            location_id UUID NULL,
            source VARCHAR(32) NOT NULL,
            window_start TIMESTAMPTZ NOT NULL,
            window_seconds INTEGER NOT NULL,
            country_code VARCHAR(8) NOT NULL,
            asn BIGINT NOT NULL,
            network_name VARCHAR(128) NULL,
            bytes_up BIGINT NOT NULL DEFAULT 0,
            bytes_down BIGINT NOT NULL DEFAULT 0,
            flows BIGINT NOT NULL DEFAULT 0,
            CONSTRAINT pk_traffic_flow_country_buckets PRIMARY KEY (id),
            CONSTRAINT fk_traffic_flow_country_buckets_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT fk_traffic_flow_country_buckets_organization_id_organizations
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
                ON DELETE SET NULL,
            CONSTRAINT fk_traffic_flow_country_buckets_location_id_locations
                FOREIGN KEY (location_id) REFERENCES locations (id)
                ON DELETE SET NULL,
            CONSTRAINT uq_traffic_flow_country_buckets_key
                UNIQUE (router_id, source, window_start, country_code, asn)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_country_buckets_window_start "
        "ON traffic_flow_country_buckets (window_start)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_country_buckets_location_window "
        "ON traffic_flow_country_buckets (location_id, window_start)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS traffic_flow_country_buckets")

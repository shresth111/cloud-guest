"""Traffic flow: service buckets, direction columns, the per-router switch.

Additive only. Nothing writes to any of it unless
``CLOUDGUEST_TRAFFIC_FLOW_ENABLED`` is true (default off).

* ``traffic_flow_windows`` gains ``bytes_up`` / ``bytes_down`` (client
  traffic by direction) and ``services_measured``. Existing rows get 0 /
  false: they were written before direction was recorded. No environment has
  a deployed collector, so in practice there are none.
* ``traffic_flow_service_buckets`` -- one row per (router, source, 5-minute
  window, protocol, remote port); see the model. Plain table, bigint
  identity. NOT day-partitioned: the 7-day delete is a bounded DELETE, the
  same as ``traffic_flow_windows``.
* ``router_traffic_flow_export`` -- the per-router switch and the last
  read-back verdict. Replaces the ``CLOUDGUEST_TRAFFIC_FLOW_ROUTER_IDS``
  allowlist.

Idempotent (``IF NOT EXISTS`` throughout), like 0154 and 0156, so an
environment that already has any of this from a sibling branch upgrades
cleanly. Not a CERT-In table set; safe to prune.

Revision ID: 0157_traffic_flow_services_export
Revises: 0156_create_traffic_flow_tables
Create Date: 2026-10-12
"""

from __future__ import annotations

from alembic import op

revision = "0157_traffic_flow_services_export"
down_revision = "0156_create_traffic_flow_tables"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def upgrade() -> None:
    op.execute(
        "ALTER TABLE traffic_flow_windows "
        "ADD COLUMN IF NOT EXISTS bytes_up BIGINT NOT NULL DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE traffic_flow_windows "
        "ADD COLUMN IF NOT EXISTS bytes_down BIGINT NOT NULL DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE traffic_flow_windows "
        "ADD COLUMN IF NOT EXISTS services_measured BOOLEAN NOT NULL DEFAULT false"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_flow_service_buckets (
            id BIGINT GENERATED ALWAYS AS IDENTITY,
            router_id UUID NOT NULL,
            organization_id UUID NULL,
            location_id UUID NULL,
            source VARCHAR(32) NOT NULL,
            window_start TIMESTAMPTZ NOT NULL,
            window_seconds INTEGER NOT NULL,
            protocol SMALLINT NOT NULL,
            remote_port INTEGER NOT NULL,
            bytes_up BIGINT NOT NULL DEFAULT 0,
            bytes_down BIGINT NOT NULL DEFAULT 0,
            flows BIGINT NOT NULL DEFAULT 0,
            CONSTRAINT pk_traffic_flow_service_buckets PRIMARY KEY (id),
            CONSTRAINT fk_traffic_flow_service_buckets_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT fk_traffic_flow_service_buckets_organization_id_organizations
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
                ON DELETE SET NULL,
            CONSTRAINT fk_traffic_flow_service_buckets_location_id_locations
                FOREIGN KEY (location_id) REFERENCES locations (id)
                ON DELETE SET NULL,
            CONSTRAINT uq_traffic_flow_service_buckets_key
                UNIQUE (router_id, source, window_start, protocol, remote_port)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_service_buckets_window_start "
        "ON traffic_flow_service_buckets (window_start)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_traffic_flow_service_buckets_location_window "
        "ON traffic_flow_service_buckets (location_id, window_start)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS router_traffic_flow_export (
            id UUID NOT NULL DEFAULT gen_random_uuid(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ NULL,
            is_deleted BOOLEAN NOT NULL DEFAULT false,
            created_by UUID NULL,
            updated_by UUID NULL,
            version INTEGER NOT NULL DEFAULT 1,
            router_id UUID NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            target_host VARCHAR(45) NULL,
            target_port INTEGER NULL,
            src_address VARCHAR(45) NULL,
            export_version VARCHAR(8) NULL,
            configured_at TIMESTAMPTZ NULL,
            last_verified_at TIMESTAMPTZ NULL,
            last_verdict_ok BOOLEAN NULL,
            last_verdict_detail TEXT NULL,
            CONSTRAINT pk_router_traffic_flow_export PRIMARY KEY (id),
            CONSTRAINT fk_router_traffic_flow_export_router_id_routers
                FOREIGN KEY (router_id) REFERENCES routers (id)
                ON DELETE CASCADE,
            CONSTRAINT uq_router_traffic_flow_export_router_id UNIQUE (router_id)
        )
        """
    )
    for column in _BASE_INDEXED:
        op.execute(
            f"CREATE INDEX IF NOT EXISTS ix_router_traffic_flow_export_{column} "
            f"ON router_traffic_flow_export ({column})"
        )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS router_traffic_flow_export")
    op.execute("DROP TABLE IF EXISTS traffic_flow_service_buckets")
    op.execute(
        "ALTER TABLE traffic_flow_windows DROP COLUMN IF EXISTS services_measured"
    )
    op.execute("ALTER TABLE traffic_flow_windows DROP COLUMN IF EXISTS bytes_down")
    op.execute("ALTER TABLE traffic_flow_windows DROP COLUMN IF EXISTS bytes_up")

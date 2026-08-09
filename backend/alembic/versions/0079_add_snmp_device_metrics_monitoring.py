"""SNMP device-metrics monitoring: per-router SNMP config + snapshot extension.

Adds real, standards-based SNMP polling support alongside the existing
RouterOS-API/SSH-based device I/O -- see
``vendor/wyfy-device-gateway/wyfy_device_gateway/snmp_poller.py`` and
``app.domains.provisioning_engine.service.run_router_snmp_metrics_poll_sweep``
for the full write-up. Two tables change, both additive-only:

``routers`` gains four nullable/defaulted SNMP-configuration columns:

* ``snmp_enabled`` (``BOOLEAN NOT NULL DEFAULT false``) -- opt-in; every
  pre-existing router has SNMP unconfigured, so ``false`` is the real,
  honest backfill for every existing row, not an assumption.
* ``snmp_community_encrypted`` (``TEXT``, nullable) -- Fernet-encrypted via
  the same ``app.domains.router.crypto`` helpers
  ``api_credentials_encrypted`` already uses.
* ``snmp_version`` (``VARCHAR(10)``, nullable) -- "1"/"2c"; ``NULL`` falls
  back to ``Settings.snmp_default_version``.
* ``snmp_port`` (``INTEGER``, nullable) -- ``NULL`` falls back to
  ``Settings.snmp_default_port`` (161).

``router_health_snapshots`` gains two nullable columns so a real SNMP-
sourced reading composes with the existing RouterOS-API-sourced history
rather than needing a second, disconnected metrics table:

* ``metrics_source`` (``VARCHAR(20)``, nullable) -- "routeros_api"/"snmp";
  ``NULL`` for every pre-existing row (predates this column, never
  fabricated as one value or the other).
* ``interface_traffic_counters`` (``JSONB``, nullable) -- real, per-
  interface SNMP IF-MIB counters for this reading; always ``NULL`` for a
  RouterOS-API-sourced snapshot (that transport has no per-interface
  breakdown here).

Revision ID: 0079_add_snmp_device_metrics_monitoring
Revises: 0078_add_qos_traffic_rule_device_push
Create Date: 2026-08-09
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0079_add_snmp_device_metrics_monitoring"
down_revision = "0078_add_qos_traffic_rule_device_push"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "routers",
        sa.Column(
            "snmp_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "routers", sa.Column("snmp_community_encrypted", sa.Text(), nullable=True)
    )
    op.add_column(
        "routers", sa.Column("snmp_version", sa.String(10), nullable=True)
    )
    op.add_column("routers", sa.Column("snmp_port", sa.Integer(), nullable=True))

    op.add_column(
        "router_health_snapshots",
        sa.Column("metrics_source", sa.String(20), nullable=True),
    )
    op.add_column(
        "router_health_snapshots",
        sa.Column(
            "interface_traffic_counters", postgresql.JSONB(), nullable=True
        ),
    )


def downgrade() -> None:
    op.drop_column("router_health_snapshots", "interface_traffic_counters")
    op.drop_column("router_health_snapshots", "metrics_source")

    op.drop_column("routers", "snmp_port")
    op.drop_column("routers", "snmp_version")
    op.drop_column("routers", "snmp_community_encrypted")
    op.drop_column("routers", "snmp_enabled")

"""Monitored-device health: current state + transition events.

Additive only. Two new tables, nothing existing is altered.

* ``monitored_device_health``: one row per probed ``connected_devices``
  row -- state/reason, up-since/down-since, debounce counter, latency,
  port link facts and port traffic.
* ``monitored_device_events``: state transitions, port link-downs and IP
  changes, for "down since", the 24h flap count and the timeline.

Revision ID: 0171_create_monitored_device_health
Revises: 0170_traffic_flow_record_ipdr_ports
Create Date: 2026-10-19
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0171_create_monitored_device_health"
down_revision = "0170_traffic_flow_record_ipdr_ports"
branch_labels = None
depends_on = None


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _ts(name: str, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _device_fk() -> sa.Column:
    return _uuid(
        "connected_device_id",
        sa.ForeignKey("connected_devices.id", ondelete="CASCADE"),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "monitored_device_health",
        _uuid("id", primary_key=True),
        _device_fk(),
        _uuid("organization_id", nullable=False),
        _uuid("location_id", nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(32), nullable=False),
        _ts("since", nullable=False),
        _ts("state_changed_at", nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        _ts("last_probe_at", nullable=False),
        _ts("last_ok_at"),
        sa.Column("last_rtt_ms", sa.Float(), nullable=True),
        sa.Column("probe_method", sa.String(8), nullable=True),
        sa.Column("port_name", sa.String(100), nullable=True),
        sa.Column("port_running", sa.Boolean(), nullable=True),
        sa.Column("port_link_downs", sa.Integer(), nullable=True),
        _ts("port_last_link_down_at"),
        _ts("port_last_link_up_at"),
        sa.Column("port_rx_bytes", sa.BigInteger(), nullable=True),
        sa.Column("port_tx_bytes", sa.BigInteger(), nullable=True),
        _ts("port_counters_at"),
        sa.Column("rx_bps", sa.BigInteger(), nullable=True),
        sa.Column("tx_bps", sa.BigInteger(), nullable=True),
        sa.Column("clients_behind", sa.Integer(), nullable=True),
    )
    op.create_index(
        "uq_monitored_device_health_connected_device_id",
        "monitored_device_health",
        ["connected_device_id"],
        unique=True,
    )
    op.create_table(
        "monitored_device_events",
        _uuid("id", primary_key=True),
        _device_fk(),
        _uuid("organization_id", nullable=False),
        _uuid("location_id", nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("from_state", sa.String(16), nullable=True),
        sa.Column("to_state", sa.String(16), nullable=True),
        sa.Column("reason", sa.String(32), nullable=True),
        sa.Column("count", sa.Integer(), nullable=True),
        sa.Column("detail", sa.String(255), nullable=True),
        _ts("occurred_at", nullable=False),
    )
    op.create_index(
        "ix_monitored_device_events_device_occurred",
        "monitored_device_events",
        ["connected_device_id", "occurred_at"],
    )
    op.create_index(
        "ix_monitored_device_events_occurred_at",
        "monitored_device_events",
        ["occurred_at"],
    )


def downgrade() -> None:
    op.drop_table("monitored_device_events")
    op.drop_table("monitored_device_health")

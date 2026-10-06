"""Device Logs (syslog): ``device_log_events`` and ``router_remote_logging``.

* ``device_log_events`` -- append-only, masked index of device syslog lines
  for the Master viewer. Plain table (bigint identity, no soft delete), see
  ``app.domains.device_logs.models``. NOT a CERT-In record table: the
  collector's raw archive is. Do not add it to the retention prune list until
  that archive is live (DESIGN §7).
* ``router_remote_logging`` -- one row per router Wyfy configured remote
  logging on, with the last read-back verdict.

Both new and empty; the feature flag (CLOUDGUEST_DEVICE_LOGS_ENABLED)
defaults off, so this migration changes no behaviour.

## Why 0150 on top of main's 0143

Built to ship to ``main`` on its own, ahead of the staging promotion, so it
chains on main's head (``0143_add_require_guest_name...``). Numbered 0150 so
its file name cannot be confused with staging's own 0144-0149 chain. On
staging this makes a second head; the staging branch carries
``0151_merge_device_logs_into_staging`` (a no-op merge revision) to join
them. When staging is promoted, main already has this exact file, and the
merge revision comes along with staging -- one head.

Revision ID: 0150_create_device_logs_tables
Revises: 0143_add_require_guest_name_to_captive_portal_configs
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0150_create_device_logs_tables"
down_revision = "0143_add_require_guest_name_to_captive_portal_configs"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _base_columns() -> list[sa.Column]:
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def upgrade() -> None:
    op.create_table(
        "device_log_events",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=True),
            primary_key=True,
        ),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("device_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("vendor", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("facility", sa.SmallInteger(), nullable=True),
        sa.Column("severity", sa.SmallInteger(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("topics", sa.String(length=200), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("attribution", sa.String(length=32), nullable=False),
        sa.Column("claimed_tag", sa.String(length=16), nullable=True),
    )
    op.create_index(
        "ix_device_log_events_received_at", "device_log_events", ["received_at"]
    )
    op.create_index(
        "ix_device_log_events_router_received",
        "device_log_events",
        ["router_id", "received_at"],
    )
    op.create_index(
        "ix_device_log_events_org_received",
        "device_log_events",
        ["organization_id", "received_at"],
    )

    op.create_table(
        "router_remote_logging",
        *_base_columns(),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("remote_host", sa.String(length=45), nullable=False),
        sa.Column("remote_port", sa.Integer(), nullable=False),
        sa.Column("src_address", sa.String(length=45), nullable=False),
        sa.Column("tag", sa.String(length=16), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("last_applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_ok", sa.Boolean(), nullable=True),
        sa.Column("verify_detail", sa.Text(), nullable=True),
        sa.UniqueConstraint("router_id", name="uq_router_remote_logging_router_id"),
    )
    for column in _BASE_INDEXED:
        op.create_index(
            f"ix_router_remote_logging_{column}", "router_remote_logging", [column]
        )


def downgrade() -> None:
    for column in reversed(_BASE_INDEXED):
        op.drop_index(
            f"ix_router_remote_logging_{column}", table_name="router_remote_logging"
        )
    op.drop_table("router_remote_logging")
    op.drop_index("ix_device_log_events_org_received", table_name="device_log_events")
    op.drop_index(
        "ix_device_log_events_router_received", table_name="device_log_events"
    )
    op.drop_index("ix_device_log_events_received_at", table_name="device_log_events")
    op.drop_table("device_log_events")

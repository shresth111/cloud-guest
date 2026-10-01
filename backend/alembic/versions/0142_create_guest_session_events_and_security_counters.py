"""``guest_session_events`` (the AAA trail) and ``security_counter_samples``
(hourly protection-rule hit counters).

``guest_session_events`` -- what the RADIUS hub and the router said about a
guest's connection: each Access-Request we answered (accept/reject + why +
what was granted) and each Accounting-Request (start, hourly-coalesced
interim, stop + cause, NAS reboot). A CERT-In connection record: never add
it to the retention prune list. See ``GuestSessionEvent``'s docstring.

``security_counter_samples`` -- one row per protection rule per router per
clock hour, written by the read-only 8728 counter collector. Operational
telemetry; safe to prune at 90 days. See ``app.domains.security.models``.

Both tables are new and empty: nothing to backfill, nothing existing is
altered, and the downgrade drops only these two.

Neither uses the ``BaseModel`` mixin columns (soft delete, created_by/
updated_by, version): append-only logs have none of those, and those were
the indexes found unused and dropped on the other log tables on 2026-09-22.

Revision ID: 0142_guest_events_security_counters
Revises: 0141_create_device_access_router_blocks
Create Date: 2026-10-01
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0142_guest_events_security_counters"
down_revision = "0141_create_device_access_router_blocks"
branch_labels = None
depends_on = None

_EVENTS = "guest_session_events"
_SAMPLES = "security_counter_samples"


def _uuid_pk() -> sa.Column:
    return sa.Column(
        "id",
        postgresql.UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.text("now()"),
    )


def _fk(name: str, table: str, *, nullable: bool, ondelete: str) -> sa.Column:
    return sa.Column(
        name,
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey(f"{table}.id", ondelete=ondelete),
        nullable=nullable,
    )


def upgrade() -> None:
    op.create_table(
        _EVENTS,
        _uuid_pk(),
        _created_at(),
        _fk("organization_id", "organizations", nullable=False, ondelete="CASCADE"),
        _fk("location_id", "locations", nullable=True, ondelete="SET NULL"),
        _fk("router_id", "routers", nullable=True, ondelete="SET NULL"),
        _fk("session_id", "guest_sessions", nullable=True, ondelete="SET NULL"),
        _fk("guest_id", "guests", nullable=True, ondelete="SET NULL"),
        sa.Column("event_type", sa.String(length=30), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("repeat_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("calling_station_id", sa.String(length=64), nullable=True),
        sa.Column("nas_identifier", sa.String(length=64), nullable=True),
        sa.Column("acct_session_id", sa.String(length=64), nullable=True),
        sa.Column("framed_ip_address", sa.String(length=45), nullable=True),
        sa.Column("nas_ip_address", sa.String(length=45), nullable=True),
        sa.Column("venue_public_ip", sa.String(length=45), nullable=True),
        sa.Column("session_time_seconds", sa.Integer(), nullable=True),
        sa.Column("bytes_uploaded_total", sa.BigInteger(), nullable=True),
        sa.Column("bytes_downloaded_total", sa.BigInteger(), nullable=True),
        sa.Column("reason_code", sa.String(length=100), nullable=True),
        sa.Column("granted", postgresql.JSONB(), nullable=True),
        sa.Column("raw", postgresql.JSONB(), nullable=True),
    )
    op.create_index(
        "ix_guest_session_events_session_id_occurred_at",
        _EVENTS,
        ["session_id", "occurred_at"],
    )
    op.create_index(
        "ix_guest_session_events_organization_id_occurred_at",
        _EVENTS,
        ["organization_id", "occurred_at"],
    )
    op.create_index(
        "ix_guest_session_events_guest_id_occurred_at",
        _EVENTS,
        ["guest_id", "occurred_at"],
    )
    op.create_index(
        "ix_guest_session_events_router_id_occurred_at",
        _EVENTS,
        ["router_id", "occurred_at"],
    )

    op.create_table(
        _SAMPLES,
        _uuid_pk(),
        _created_at(),
        _fk("organization_id", "organizations", nullable=False, ondelete="CASCADE"),
        _fk("location_id", "locations", nullable=True, ondelete="CASCADE"),
        _fk("router_id", "routers", nullable=False, ondelete="CASCADE"),
        sa.Column("protection", sa.String(length=40), nullable=False),
        sa.Column("rule_key", sa.String(length=160), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sampled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("packets_total", sa.BigInteger(), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("packets_delta", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_delta", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.create_index(
        "uq_security_counter_samples_router_rule_bucket",
        _SAMPLES,
        ["router_id", "rule_key", "bucket_start"],
        unique=True,
    )
    op.create_index(
        "ix_security_counter_samples_org_bucket",
        _SAMPLES,
        ["organization_id", "bucket_start"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_counter_samples_org_bucket", table_name=_SAMPLES)
    op.drop_index("uq_security_counter_samples_router_rule_bucket", table_name=_SAMPLES)
    op.drop_table(_SAMPLES)
    for name in (
        "router_id_occurred_at",
        "guest_id_occurred_at",
        "organization_id_occurred_at",
        "session_id_occurred_at",
    ):
        op.drop_index(f"ix_{_EVENTS}_{name}", table_name=_EVENTS)
    op.drop_table(_EVENTS)

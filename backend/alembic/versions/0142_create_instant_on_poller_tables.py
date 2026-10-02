"""Aruba Instant On read-only poller: ``instant_on_sites``,
``instant_on_snapshots``, ``instant_on_account_tokens``.

* ``instant_on_sites`` -- one live row per NAS-only fleet router: which
  Instant On site it is, the per-venue poll / customer-visible flags, and the
  last poll's outcome.
* ``instant_on_snapshots`` -- the latest normalized read per (site, kind),
  upserted in place (unique on the pair), never appended per poll.
* ``instant_on_account_tokens`` -- the service account's encrypted, rotating
  OAuth tokens, shared by every worker.

See ``app.domains.network_integration.models`` for the reasoning. All three
are new and empty; nothing to backfill, and both flags default to false, so
this migration changes no venue's behaviour.

Downgrade drops the three tables (the tokens with them: the next poll after a
re-upgrade does a fresh service-account login).

Revision ID: 0142_create_instant_on_poller_tables
Revises: 0141_create_device_access_router_blocks
Create Date: 2026-10-02
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0142_create_instant_on_poller_tables"
down_revision = "0141_create_device_access_router_blocks"
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


def _base_indexes(table: str) -> None:
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{column}", table, [column])


def _drop_base_indexes(table: str) -> None:
    for column in reversed(_BASE_INDEXED):
        op.drop_index(f"ix_{table}_{column}", table_name=table)


def upgrade() -> None:
    op.create_table(
        "instant_on_sites",
        *_base_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("site_name", sa.String(length=255), nullable=True),
        sa.Column(
            "poll_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "customer_visible",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "api_state",
            sa.String(length=30),
            nullable=False,
            server_default="never_polled",
        ),
        sa.Column("last_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "consecutive_failures", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("backoff_until", sa.DateTime(timezone=True), nullable=True),
    )
    _base_indexes("instant_on_sites")
    op.create_index(
        "ix_instant_on_sites_organization_id", "instant_on_sites", ["organization_id"]
    )
    op.create_index(
        "ix_instant_on_sites_location_id", "instant_on_sites", ["location_id"]
    )
    op.create_index(
        "uq_instant_on_sites_router_id",
        "instant_on_sites",
        ["router_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )

    op.create_table(
        "instant_on_snapshots",
        *_base_columns(),
        sa.Column(
            "instant_on_site_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("instant_on_sites.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
        sa.Column("payload_hash", sa.String(length=64), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_attempt_ok",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    _base_indexes("instant_on_snapshots")
    op.create_index(
        "uq_instant_on_snapshots_site_kind",
        "instant_on_snapshots",
        ["instant_on_site_id", "kind"],
        unique=True,
    )
    op.create_index(
        "ix_instant_on_snapshots_organization_id",
        "instant_on_snapshots",
        ["organization_id"],
    )

    op.create_table(
        "instant_on_account_tokens",
        *_base_columns(),
        sa.Column("account_key", sa.String(length=64), nullable=False),
        sa.Column("tokens_encrypted", sa.Text(), nullable=True),
        sa.Column("access_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("refresh_obtained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "auth_state", sa.String(length=30), nullable=False, server_default="never"
        ),
        sa.Column("auth_error_code", sa.String(length=64), nullable=True),
        sa.Column("login_blocked_until", sa.DateTime(timezone=True), nullable=True),
    )
    _base_indexes("instant_on_account_tokens")
    op.create_index(
        "uq_instant_on_account_tokens_account_key",
        "instant_on_account_tokens",
        ["account_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_instant_on_account_tokens_account_key",
        table_name="instant_on_account_tokens",
    )
    _drop_base_indexes("instant_on_account_tokens")
    op.drop_table("instant_on_account_tokens")

    op.drop_index(
        "ix_instant_on_snapshots_organization_id", table_name="instant_on_snapshots"
    )
    op.drop_index(
        "uq_instant_on_snapshots_site_kind", table_name="instant_on_snapshots"
    )
    _drop_base_indexes("instant_on_snapshots")
    op.drop_table("instant_on_snapshots")

    op.drop_index("uq_instant_on_sites_router_id", table_name="instant_on_sites")
    op.drop_index("ix_instant_on_sites_location_id", table_name="instant_on_sites")
    op.drop_index("ix_instant_on_sites_organization_id", table_name="instant_on_sites")
    _drop_base_indexes("instant_on_sites")
    op.drop_table("instant_on_sites")

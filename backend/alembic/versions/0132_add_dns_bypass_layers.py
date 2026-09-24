"""DNS bypass layers: per-router layer set and the platform DoH lists.

Additive only:

* ``dns_filtering_router_locations`` gains ``bypass_layers`` (which of the
  individually switchable bypass layers are on; ``[]`` for every existing
  row, i.e. nothing changes for a router until someone turns a layer on),
  ``bypass_lists_sha`` and ``bypass_lists_pushed_at`` (which version of the
  platform DoH lists that router last received).
* ``dns_bypass_blocklists`` -- platform-owned, one row per list kind
  (DoH IPv4, DoH IPv6, DoH hostnames): the last *good* copy of the public
  list, fetched once for the whole platform.

Backfill: a router that already had #307's bypass hardening on is given
that PR's three layers (DoT ports, DoH by IP, plain-DNS redirect), which is
exactly what is on the device. Nothing is written to any router.

Downgrade drops the table and the columns. Any router with a layer on keeps
its rows on the device; disable bypass hardening first.

Revision ID: 0132_add_dns_bypass_layers
Revises: 0131_create_dns_filtering_tables
Create Date: 2026-09-24
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0132_add_dns_bypass_layers"
down_revision = "0131_create_dns_filtering_tables"
branch_labels = None
depends_on = None

_TABLE = "dns_filtering_router_locations"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "bypass_layers",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        _TABLE, sa.Column("bypass_lists_sha", sa.String(length=64), nullable=True)
    )
    op.add_column(
        _TABLE,
        sa.Column("bypass_lists_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        f"UPDATE {_TABLE} SET bypass_layers = "
        "'[\"encrypted_dns_ports\", \"doh_ip_list\", \"plain_dns_redirect\"]'::jsonb "
        "WHERE bypass_hardening_enabled = true"
    )

    op.create_table(
        "dns_bypass_blocklists",
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
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("entries", postgresql.JSONB(), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=20), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    for column in _BASE_INDEXED:
        op.create_index(
            f"ix_dns_bypass_blocklists_{column}", "dns_bypass_blocklists", [column]
        )
    op.create_index(
        "uq_dns_bypass_blocklists_kind",
        "dns_bypass_blocklists",
        ["kind"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_table("dns_bypass_blocklists")
    op.drop_column(_TABLE, "bypass_lists_pushed_at")
    op.drop_column(_TABLE, "bypass_lists_sha")
    op.drop_column(_TABLE, "bypass_layers")

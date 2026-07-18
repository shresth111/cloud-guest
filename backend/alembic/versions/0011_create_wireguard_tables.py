"""Create WireGuard domain tables: wireguard_servers, wireguard_peers.

Mirrors ``0010_create_router_agent_tables``'s conventions: each table gets
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is Module 009 Part 3's only migration -- two new tables:

* ``wireguard_servers`` -- platform-operated WireGuard hubs. No FK to any
  existing table.
* ``wireguard_peers`` -- one row per router with a tunnel, referencing both
  ``routers.id`` (an existing table, unchanged) and ``wireguard_servers.id``
  (created in this same migration).

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): neither table is referenced by any RBAC scope column.

Revision ID: 0011_create_wireguard_tables
Revises: 0010_create_router_agent_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0011_create_wireguard_tables"
down_revision = "0010_create_router_agent_tables"
branch_labels = None
depends_on = None


def _base_model_columns() -> list[sa.Column]:
    """Columns provided by ``app.database.base.BaseModel`` for every table."""
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def upgrade() -> None:
    op.create_table(
        "wireguard_servers",
        *_base_model_columns(),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("endpoint_host", sa.String(255), nullable=False),
        sa.Column(
            "endpoint_port", sa.Integer(), nullable=False, server_default="51820"
        ),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column("tunnel_network_cidr", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("public_key", name="uq_wireguard_servers_public_key"),
    )
    _create_base_model_indexes("wireguard_servers")
    op.create_index(
        "ix_wireguard_servers_is_active", "wireguard_servers", ["is_active"]
    )
    op.create_index(
        "ix_wireguard_servers_public_key",
        "wireguard_servers",
        ["public_key"],
        unique=True,
    )

    op.create_table(
        "wireguard_peers",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tunnel_ip_address", sa.String(45), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("rotation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_handshake_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_wireguard_peers_router_id_routers",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["wireguard_servers.id"],
            name="fk_wireguard_peers_server_id_wireguard_servers",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("router_id", name="uq_wireguard_peers_router_id"),
        sa.UniqueConstraint("public_key", name="uq_wireguard_peers_public_key"),
        sa.UniqueConstraint(
            "server_id",
            "tunnel_ip_address",
            name="uq_wireguard_peers_server_id_tunnel_ip_address",
        ),
    )
    _create_base_model_indexes("wireguard_peers")
    op.create_index(
        "ix_wireguard_peers_router_id", "wireguard_peers", ["router_id"], unique=True
    )
    op.create_index("ix_wireguard_peers_server_id", "wireguard_peers", ["server_id"])
    op.create_index("ix_wireguard_peers_status", "wireguard_peers", ["status"])
    op.create_index(
        "ix_wireguard_peers_tunnel_ip_address",
        "wireguard_peers",
        ["tunnel_ip_address"],
    )


def downgrade() -> None:
    op.drop_index("ix_wireguard_peers_tunnel_ip_address", table_name="wireguard_peers")
    op.drop_index("ix_wireguard_peers_status", table_name="wireguard_peers")
    op.drop_index("ix_wireguard_peers_server_id", table_name="wireguard_peers")
    op.drop_index("ix_wireguard_peers_router_id", table_name="wireguard_peers")
    _drop_base_model_indexes("wireguard_peers")
    op.drop_table("wireguard_peers")

    op.drop_index("ix_wireguard_servers_public_key", table_name="wireguard_servers")
    op.drop_index("ix_wireguard_servers_is_active", table_name="wireguard_servers")
    _drop_base_model_indexes("wireguard_servers")
    op.drop_table("wireguard_servers")

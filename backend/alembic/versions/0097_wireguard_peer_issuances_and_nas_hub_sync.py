"""Hub reconciliation: the WireGuard issuance ledger, and the NAS row's
record of what the hub actually confirmed.

Two additions, one incident.

``wireguard_peer_issuances`` is append-only history of every (router,
public key, tunnel address) this platform has handed out. ``wireguard_peers``
holds one row per router and overwrites it on every re-allocation, which is
fine for a hub that can be told to forget the peer it replaced -- and this
hub cannot (``ops/hub-agents/wg_agent.py`` has no DELETE verb). So the
overwritten row was the only record that a still-live peer on the hub
belonged to a known router, and destroying it is what made six of the seven
peers on the production hub unattributable on 2026-08-27. See
``app.domains.wireguard.models.WireGuardPeerIssuance``.

``radius_nas_clients.hub_client_synced_ip``/``_at`` record what the hub
CONFIRMED it wrote into ``clients.conf``, as distinct from what this
platform intended. That distinction had no column at all: the address every
guest Access-Request is matched against was derived at registration time
from ``peer.tunnel_ip_address`` and thrown away, so a peer moving from
10.20.0.6 to 10.20.0.8 broke a venue with every row still looking healthy.

Purely additive. No existing column changes type or nullability, nothing is
backfilled, and both new tables/columns are nullable or empty on arrival --
so this migration cannot fail on existing data and needs no downtime. What
it deliberately does NOT do is invent history: the ledger starts empty, and
the seven peers already on the hub stay unattributable until an operator
adopts them through
``POST /wireguard/hub-peers/{public_key}/adopt``. Guessing which router each
belonged to, from an audit trail that never recorded a public key, would be
exactly the confident-and-wrong behaviour the ledger exists to end.

Revision ID: 0097_wireguard_peer_issuances_and_nas_hub_sync
Revises: 0096_create_demo_bookings_table
Create Date: 2026-08-27
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0097_wireguard_peer_issuances_and_nas_hub_sync"
down_revision = "0096_create_demo_bookings_table"
branch_labels = None
depends_on = None

_TABLE = "wireguard_peer_issuances"


def _base_model_columns() -> list[sa.Column]:
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
        _TABLE,
        *_base_model_columns(),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("wireguard_servers.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("tunnel_ip_address", sa.String(length=45), nullable=False),
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column("hub_lifecycle", sa.String(length=30), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
    )
    _create_base_model_indexes(_TABLE)
    # NOT unique on public_key: one key can legitimately be recorded twice
    # for a router (issued, then adopted once the device proved it was using
    # it), and those are two different facts. Uniqueness stays on
    # wireguard_peers, where it describes the platform's current belief
    # rather than its history.
    op.create_index(f"ix_{_TABLE}_router_id", _TABLE, ["router_id"])
    op.create_index(f"ix_{_TABLE}_public_key", _TABLE, ["public_key"])
    op.create_index(f"ix_{_TABLE}_server_id", _TABLE, ["server_id"])
    op.create_index(f"ix_{_TABLE}_hub_lifecycle", _TABLE, ["hub_lifecycle"])

    op.add_column(
        "radius_nas_clients",
        sa.Column("hub_client_synced_ip", sa.String(length=45), nullable=True),
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column(
            "hub_client_synced_at", sa.DateTime(timezone=True), nullable=True
        ),
    )


def downgrade() -> None:
    op.drop_column("radius_nas_clients", "hub_client_synced_at")
    op.drop_column("radius_nas_clients", "hub_client_synced_ip")
    op.drop_index(f"ix_{_TABLE}_hub_lifecycle", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_server_id", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_public_key", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_router_id", table_name=_TABLE)
    _drop_base_model_indexes(_TABLE)
    op.drop_table(_TABLE)

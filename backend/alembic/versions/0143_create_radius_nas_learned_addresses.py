"""NAS-only egress auto-learn: ``radius_nas_learned_addresses``.

One row per public egress address learned for a NAS-only (Aruba Instant
On) device from its guests' portal traffic; each is written to the hub as
an additional ``client{}`` stanza. See ``app.domains.guest.nas_egress``.

New and empty; the feature is off unless
``CLOUDGUEST_NAS_EGRESS_LEARNING_ENABLED`` is set, so this migration changes
no venue's behaviour. Downgrade drops the table (the hub keeps whatever
stanzas it has until the next push for that NAS, which rewrites its set).

Revision ID: 0143_create_radius_nas_learned_addresses
Revises: 0142_create_instant_on_poller_tables
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0143_create_radius_nas_learned_addresses"
down_revision = "0142_create_instant_on_poller_tables"
branch_labels = None
depends_on = None

_TABLE = "radius_nas_learned_addresses"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")
_OWN_INDEXED = ("nas_client_id", "router_id", "ip_address")


def upgrade() -> None:
    op.create_table(
        _TABLE,
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
        sa.Column(
            "nas_client_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("radius_nas_clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("hub_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "nas_client_id", "ip_address", name="uq_radius_nas_learned_address"
        ),
    )
    for column in (*_BASE_INDEXED, *_OWN_INDEXED):
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])


def downgrade() -> None:
    for column in reversed((*_BASE_INDEXED, *_OWN_INDEXED)):
        op.drop_index(f"ix_{_TABLE}_{column}", table_name=_TABLE)
    op.drop_table(_TABLE)

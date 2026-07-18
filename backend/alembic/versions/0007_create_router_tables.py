"""Create Router domain tables: routers, router_provisioning_tokens.

Mirrors ``0005_create_location_tables``'s conventions: each table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported, since Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Note on migration numbering: Module 007 (``app.domains.user``) added no
migration of its own -- it is a pure aggregation/composition layer over
``auth``/``organization``/``rbac`` with no persisted model. This is
therefore ``0007`` (not ``0008``), immediately following ``0006_add_location_
fk_to_rbac_tables``.

``routers.location_id`` is a real, ``NOT NULL`` FK to ``locations.id``
(``ON DELETE CASCADE`` -- a router has no meaning once its owning location is
gone, mirroring ``locations.organization_id``'s own reasoning).
``routers.organization_id`` is a *denormalized* real, ``NOT NULL`` FK to
``organizations.id`` (``ON DELETE CASCADE``) -- see
``docs/router/ROUTER_ARCHITECTURE.md`` §1 for why this was chosen over
deriving the organization solely via a join through ``locations``.
``serial_number``/``mac_address`` are globally unique (hardware identifiers,
not scoped to a tenant).

``router_provisioning_tokens.router_id`` is a real, ``NOT NULL`` FK to
``routers.id`` (``ON DELETE CASCADE`` -- a provisioning token has no meaning
once its router is gone). ``token_hash`` is unique (a SHA-256 digest of the
plaintext bearer token, never the plaintext itself -- see
``docs/router/ROUTER_ARCHITECTURE.md`` §5).

Revision ID: 0007_create_router_tables
Revises: 0006_add_location_fk_to_rbac_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0007_create_router_tables"
down_revision = "0006_add_location_fk_to_rbac_tables"
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
        "routers",
        *_base_model_columns(),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("serial_number", sa.String(100), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("routeros_version", sa.String(50), nullable=True),
        sa.Column("management_ip_address", sa.String(45), nullable=True),
        sa.Column("public_ip_address", sa.String(45), nullable=True),
        sa.Column(
            "status",
            sa.String(30),
            nullable=False,
            server_default="pending_provisioning",
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health_status", sa.String(20), nullable=True),
        sa.Column("api_username", sa.String(100), nullable=True),
        sa.Column("api_credentials_encrypted", sa.Text(), nullable=True),
        sa.Column(
            "settings",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_routers_location_id_locations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_routers_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("serial_number", name="uq_routers_serial_number"),
        sa.UniqueConstraint("mac_address", name="uq_routers_mac_address"),
    )
    _create_base_model_indexes("routers")
    op.create_index("ix_routers_location_id", "routers", ["location_id"])
    op.create_index("ix_routers_organization_id", "routers", ["organization_id"])
    op.create_index("ix_routers_serial_number", "routers", ["serial_number"])
    op.create_index("ix_routers_mac_address", "routers", ["mac_address"])
    op.create_index("ix_routers_status", "routers", ["status"])
    op.create_index("ix_routers_name", "routers", ["name"])

    op.create_table(
        "router_provisioning_tokens",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_router_provisioning_tokens_router_id_routers",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_router_provisioning_tokens_created_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "token_hash", name="uq_router_provisioning_tokens_token_hash"
        ),
    )
    _create_base_model_indexes("router_provisioning_tokens")
    op.create_index(
        "ix_router_provisioning_tokens_router_id",
        "router_provisioning_tokens",
        ["router_id"],
    )
    op.create_index(
        "ix_router_provisioning_tokens_expires_at",
        "router_provisioning_tokens",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_router_provisioning_tokens_expires_at",
        table_name="router_provisioning_tokens",
    )
    op.drop_index(
        "ix_router_provisioning_tokens_router_id",
        table_name="router_provisioning_tokens",
    )
    _drop_base_model_indexes("router_provisioning_tokens")
    op.drop_table("router_provisioning_tokens")

    op.drop_index("ix_routers_name", table_name="routers")
    op.drop_index("ix_routers_status", table_name="routers")
    op.drop_index("ix_routers_mac_address", table_name="routers")
    op.drop_index("ix_routers_serial_number", table_name="routers")
    op.drop_index("ix_routers_organization_id", table_name="routers")
    op.drop_index("ix_routers_location_id", table_name="routers")
    _drop_base_model_indexes("routers")
    op.drop_table("routers")

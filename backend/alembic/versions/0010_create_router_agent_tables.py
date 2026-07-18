"""Create Router Agent domain table: router_agent_credentials.

Mirrors ``0009_create_router_provisioning_tables``'s conventions: the table
gets the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is Module 009 Part 2's only migration -- one new table
(``router_agent_credentials``), referencing ``routers.id`` (an existing
table, unchanged). No RBAC FK follow-up migration is needed (unlike Modules
005/006/008's own follow-ups): this table is not referenced by any RBAC
scope column.

Revision ID: 0010_create_router_agent_tables
Revises: 0009_create_router_provisioning_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0010_create_router_agent_tables"
down_revision = "0009_create_router_provisioning_tables"
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
        "router_agent_credentials",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_hash", sa.String(128), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agent_software_version", sa.String(100), nullable=True),
        sa.Column(
            "capabilities",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("license_key", sa.String(255), nullable=True),
        sa.Column(
            "license_status", sa.String(20), nullable=False, server_default="unknown"
        ),
        sa.Column("last_status_report_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_router_agent_credentials_router_id_routers",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("router_id", name="uq_router_agent_credentials_router_id"),
        sa.UniqueConstraint(
            "credential_hash", name="uq_router_agent_credentials_credential_hash"
        ),
    )
    _create_base_model_indexes("router_agent_credentials")
    op.create_index(
        "ix_router_agent_credentials_router_id",
        "router_agent_credentials",
        ["router_id"],
        unique=True,
    )
    op.create_index(
        "ix_router_agent_credentials_credential_hash",
        "router_agent_credentials",
        ["credential_hash"],
        unique=True,
    )
    op.create_index(
        "ix_router_agent_credentials_expires_at",
        "router_agent_credentials",
        ["expires_at"],
    )
    op.create_index(
        "ix_router_agent_credentials_revoked_at",
        "router_agent_credentials",
        ["revoked_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_router_agent_credentials_revoked_at",
        table_name="router_agent_credentials",
    )
    op.drop_index(
        "ix_router_agent_credentials_expires_at",
        table_name="router_agent_credentials",
    )
    op.drop_index(
        "ix_router_agent_credentials_credential_hash",
        table_name="router_agent_credentials",
    )
    op.drop_index(
        "ix_router_agent_credentials_router_id",
        table_name="router_agent_credentials",
    )
    _drop_base_model_indexes("router_agent_credentials")
    op.drop_table("router_agent_credentials")

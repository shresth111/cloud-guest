"""DNS Management domain: ``dns_records``.

New domain (``app.domains.dns``) -- per-router static DNS record
inventory (A/AAAA/CNAME), mirroring ``app.domains.dhcp``'s own "plain
rules/inventory domain, pushed via app.domains.network_config's existing
provisioning pipeline" shape. One new table, additive only.

No RBAC schema change -- ``PermissionModule.DNS`` was already seeded
(scope ``ROUTER``, actions CREATE/READ/UPDATE/DELETE/MANAGE) before this
domain existed to claim it (per this codebase's own established
convention -- see e.g. migration ``0048``'s identical note). Three
additive ``AuditAction`` enum values (``DNS_RECORD_CREATED``/``_UPDATED``/
``_DELETED``) need no migration either (seeded idempotently by
``seed_rbac``/written directly by the service, never by a migration).

Revision ID: 0052_create_dns_tables
Revises: 0051_add_mfa_support
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0052_create_dns_tables"
down_revision = "0051_add_mfa_support"
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
        "dns_records",
        *_base_model_columns(),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
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
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("record_type", sa.String(10), nullable=False, server_default="a"),
        sa.Column("address", sa.String(255), nullable=False),
        sa.Column(
            "ttl_seconds", sa.Integer(), nullable=False, server_default="86400"
        ),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    _create_base_model_indexes("dns_records")
    op.create_index("ix_dns_records_router_id", "dns_records", ["router_id"])
    op.create_index(
        "ix_dns_records_organization_id", "dns_records", ["organization_id"]
    )
    op.create_index("ix_dns_records_location_id", "dns_records", ["location_id"])
    op.create_index("ix_dns_records_name", "dns_records", ["name"])
    op.create_index("ix_dns_records_is_enabled", "dns_records", ["is_enabled"])


def downgrade() -> None:
    op.drop_index("ix_dns_records_is_enabled", table_name="dns_records")
    op.drop_index("ix_dns_records_name", table_name="dns_records")
    op.drop_index("ix_dns_records_location_id", table_name="dns_records")
    op.drop_index("ix_dns_records_organization_id", table_name="dns_records")
    op.drop_index("ix_dns_records_router_id", table_name="dns_records")
    _drop_base_model_indexes("dns_records")
    op.drop_table("dns_records")

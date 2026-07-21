"""Firewall Rule Management domain: ``firewall_rules``.

New domain (``app.domains.firewall``) -- per-router generic ALLOW/DROP/
REJECT packet-filter rule inventory, distinct from
``app.domains.port_forwarding``'s NAT/DSTNAT-only concern (which already,
deliberately, reuses this same ``PermissionModule.FIREWALL`` key -- see
that domain's own router docstring). One new table, additive only.

No RBAC schema change -- ``PermissionModule.FIREWALL`` was already seeded
(scope ``ROUTER``, actions CREATE/READ/UPDATE/DELETE/EXECUTE/MANAGE)
before this domain existed to claim it (per this codebase's own
established convention). Three additive ``AuditAction`` enum values
(``FIREWALL_RULE_CREATED``/``_UPDATED``/``_DELETED``) need no migration
either.

Revision ID: 0053_create_firewall_tables
Revises: 0052_create_dns_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0053_create_firewall_tables"
down_revision = "0052_create_dns_tables"
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
        "firewall_rules",
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
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("chain", sa.String(20), nullable=False, server_default="forward"),
        sa.Column("action", sa.String(20), nullable=False, server_default="accept"),
        sa.Column("protocol", sa.String(10), nullable=False, server_default="all"),
        sa.Column("source_address", sa.String(64), nullable=True),
        sa.Column("destination_address", sa.String(64), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("in_interface", sa.String(100), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    _create_base_model_indexes("firewall_rules")
    op.create_index("ix_firewall_rules_router_id", "firewall_rules", ["router_id"])
    op.create_index(
        "ix_firewall_rules_organization_id", "firewall_rules", ["organization_id"]
    )
    op.create_index(
        "ix_firewall_rules_location_id", "firewall_rules", ["location_id"]
    )
    op.create_index("ix_firewall_rules_chain", "firewall_rules", ["chain"])
    op.create_index("ix_firewall_rules_priority", "firewall_rules", ["priority"])
    op.create_index(
        "ix_firewall_rules_is_enabled", "firewall_rules", ["is_enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_firewall_rules_is_enabled", table_name="firewall_rules")
    op.drop_index("ix_firewall_rules_priority", table_name="firewall_rules")
    op.drop_index("ix_firewall_rules_chain", table_name="firewall_rules")
    op.drop_index("ix_firewall_rules_location_id", table_name="firewall_rules")
    op.drop_index("ix_firewall_rules_organization_id", table_name="firewall_rules")
    op.drop_index("ix_firewall_rules_router_id", table_name="firewall_rules")
    _drop_base_model_indexes("firewall_rules")
    op.drop_table("firewall_rules")

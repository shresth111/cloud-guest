"""Port Forwarding Management domain: ``port_forwarding_rules``.

New domain (``app.domains.port_forwarding``), a per-router DSTNAT rule
inventory (see ``service.py``'s own module docstring). One new table,
additive only:

* ``port_forwarding_rules`` -- one row per port-forwarding (NAT DSTNAT)
  rule a router carries. No database-level conflict constraint -- see
  ``models.py``'s own module docstring for why conflict detection is a
  service-layer check only (a real, honest gap, not silently assumed
  away).

A pure rules/inventory domain -- no live device push, no history table:
a row's own state *is* its current state, and real RouterOS
``/ip firewall nat`` DSTNAT provisioning is deferred to the not-yet-built
Network Configuration Management domain's own provisioning-integration
layer.

No RBAC schema change at all -- this domain reuses the already-seeded
``PermissionModule.FIREWALL`` key (port forwarding is a real RouterOS
firewall/NAT concept), the same reuse posture ``app.domains.dhcp``
established for the pre-existing ``PermissionModule.DHCP``. Only additive
``AuditAction`` enum values (``PORT_FORWARDING_RULE_CREATED``/
``PORT_FORWARDING_RULE_UPDATED``/``PORT_FORWARDING_RULE_DELETED``) are
added -- no migration needed for any of that
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0039``'s identical note).

Revision ID: 0040_create_port_forwarding_tables
Revises: 0039_create_dhcp_pool_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0040_create_port_forwarding_tables"
down_revision = "0039_create_dhcp_pool_tables"
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
        "port_forwarding_rules",
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
        sa.Column("protocol", sa.String(10), nullable=False, server_default="both"),
        sa.Column("source_address", sa.String(64), nullable=True),
        sa.Column("destination_address", sa.String(64), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("internal_address", sa.String(45), nullable=False),
        sa.Column("internal_port", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("port_forwarding_rules")
    op.create_index(
        "ix_port_forwarding_rules_router_id", "port_forwarding_rules", ["router_id"]
    )
    op.create_index(
        "ix_port_forwarding_rules_organization_id",
        "port_forwarding_rules",
        ["organization_id"],
    )
    op.create_index(
        "ix_port_forwarding_rules_location_id",
        "port_forwarding_rules",
        ["location_id"],
    )
    op.create_index(
        "ix_port_forwarding_rules_destination_port",
        "port_forwarding_rules",
        ["destination_port"],
    )
    op.create_index(
        "ix_port_forwarding_rules_is_enabled",
        "port_forwarding_rules",
        ["is_enabled"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_port_forwarding_rules_is_enabled", table_name="port_forwarding_rules"
    )
    op.drop_index(
        "ix_port_forwarding_rules_destination_port",
        table_name="port_forwarding_rules",
    )
    op.drop_index(
        "ix_port_forwarding_rules_location_id", table_name="port_forwarding_rules"
    )
    op.drop_index(
        "ix_port_forwarding_rules_organization_id",
        table_name="port_forwarding_rules",
    )
    op.drop_index(
        "ix_port_forwarding_rules_router_id", table_name="port_forwarding_rules"
    )
    _drop_base_model_indexes("port_forwarding_rules")
    op.drop_table("port_forwarding_rules")

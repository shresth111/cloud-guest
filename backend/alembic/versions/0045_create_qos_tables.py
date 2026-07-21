"""QoS & VOIP Priority domain: ``qos_traffic_rules``.

New domain (``app.domains.qos``), a per-router traffic-classification
rule inventory (see ``service.py``'s own module docstring). One new
table, additive only:

* ``qos_traffic_rules`` -- one row per traffic-classification rule a
  router applies (protocol/port-range match for VOIP signaling/media, or
  DSCP value, mapped to a priority). No database-level constraint
  enforcing "exactly one match kind" -- see ``models.py``'s own module
  docstring for why this is a service-layer check only
  (``validators.validate_traffic_match``).

A pure rules/inventory domain -- no live device push, no history table:
a row's own state *is* its current state, and real RouterOS
``/ip firewall mangle`` provisioning is composed via the already-built
Network Configuration Management domain (``app.domains.network_config``),
not this domain.

No RBAC schema change beyond a brand-new, additive ``PermissionModule
.QOS`` seeded module (``rbac/enums.py``/``rbac/seed.py``) plus additive
``AuditAction`` enum values (``QOS_TRAFFIC_RULE_CREATED``/
``QOS_TRAFFIC_RULE_UPDATED``/``QOS_TRAFFIC_RULE_DELETED``) -- no
migration needed for any of those (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded
idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0039``'s identical note).

Revision ID: 0045_create_qos_tables
Revises: 0044_create_hotspot_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0045_create_qos_tables"
down_revision = "0044_create_hotspot_tables"
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
        "qos_traffic_rules",
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
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("port_range_start", sa.Integer(), nullable=True),
        sa.Column("port_range_end", sa.Integer(), nullable=True),
        sa.Column("dscp_value", sa.Integer(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="8"),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("qos_traffic_rules")
    op.create_index(
        "ix_qos_traffic_rules_router_id", "qos_traffic_rules", ["router_id"]
    )
    op.create_index(
        "ix_qos_traffic_rules_organization_id",
        "qos_traffic_rules",
        ["organization_id"],
    )
    op.create_index(
        "ix_qos_traffic_rules_location_id", "qos_traffic_rules", ["location_id"]
    )
    op.create_index(
        "ix_qos_traffic_rules_is_enabled", "qos_traffic_rules", ["is_enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_qos_traffic_rules_is_enabled", table_name="qos_traffic_rules")
    op.drop_index("ix_qos_traffic_rules_location_id", table_name="qos_traffic_rules")
    op.drop_index(
        "ix_qos_traffic_rules_organization_id", table_name="qos_traffic_rules"
    )
    op.drop_index("ix_qos_traffic_rules_router_id", table_name="qos_traffic_rules")
    _drop_base_model_indexes("qos_traffic_rules")
    op.drop_table("qos_traffic_rules")

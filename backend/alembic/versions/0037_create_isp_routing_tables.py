"""ISP Routing domain: ``isp_routing_rules``.

New domain (``app.domains.isp_routing``), a per-router traffic-steering
rules inventory deciding which ``isp_links`` row a piece of traffic routes
through (see ``service.py``'s own module docstring). One new table,
additive only:

* ``isp_routing_rules`` -- one row per rule. A ``rule_type`` discriminator
  (``constants.IspRoutingRuleType``: vlan/user/ip/source/interface/policy)
  with exactly one of six per-type match columns populated (``vlan_id``/
  ``source_mac_address``/``ip_address``/``source_cidr``/
  ``interface_name``/``policy_id``), enforced at the service layer, not the
  database layer (mirrors every other domain's own "type discriminator +
  service-level match validation, not a CHECK constraint" convention).

A pure rules/inventory domain -- no live device push, no history table (see
``models.py``'s own module docstring): a rule's own row *is* its current
state, and real RouterOS ``/ip firewall mangle``/``/routing table``
plumbing is deferred to the not-yet-built Network Configuration Management
domain's own provisioning-integration layer.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.ISP_ROUTING`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus additive ``AuditAction`` enum values
(``ISP_ROUTING_RULE_CREATED``/``ISP_ROUTING_RULE_UPDATED``/
``ISP_ROUTING_RULE_DELETED``) -- no migration needed for any of those
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0036``'s identical note).

Revision ID: 0037_create_isp_routing_tables
Revises: 0036_create_isp_management_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0037_create_isp_routing_tables"
down_revision = "0036_create_isp_management_tables"
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
        "isp_routing_rules",
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
        sa.Column(
            "isp_link_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("isp_links.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_type", sa.String(20), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("source_mac_address", sa.String(17), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("source_cidr", sa.String(64), nullable=True),
        sa.Column("interface_name", sa.String(100), nullable=True),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("policies.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    _create_base_model_indexes("isp_routing_rules")
    op.create_index(
        "ix_isp_routing_rules_router_id", "isp_routing_rules", ["router_id"]
    )
    op.create_index(
        "ix_isp_routing_rules_organization_id",
        "isp_routing_rules",
        ["organization_id"],
    )
    op.create_index(
        "ix_isp_routing_rules_location_id", "isp_routing_rules", ["location_id"]
    )
    op.create_index(
        "ix_isp_routing_rules_isp_link_id", "isp_routing_rules", ["isp_link_id"]
    )
    op.create_index(
        "ix_isp_routing_rules_rule_type", "isp_routing_rules", ["rule_type"]
    )
    op.create_index(
        "ix_isp_routing_rules_is_enabled", "isp_routing_rules", ["is_enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_isp_routing_rules_is_enabled", table_name="isp_routing_rules")
    op.drop_index("ix_isp_routing_rules_rule_type", table_name="isp_routing_rules")
    op.drop_index("ix_isp_routing_rules_isp_link_id", table_name="isp_routing_rules")
    op.drop_index("ix_isp_routing_rules_location_id", table_name="isp_routing_rules")
    op.drop_index(
        "ix_isp_routing_rules_organization_id", table_name="isp_routing_rules"
    )
    op.drop_index("ix_isp_routing_rules_router_id", table_name="isp_routing_rules")
    _drop_base_model_indexes("isp_routing_rules")
    op.drop_table("isp_routing_rules")

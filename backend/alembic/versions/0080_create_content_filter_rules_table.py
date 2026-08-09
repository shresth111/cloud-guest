"""Content Filtering domain: ``content_filter_rules``.

New domain (``app.domains.content_filtering``) -- real, per-router
content-filtering rules for the colleges/PGs/hostels segment (parents/
wardens routinely want basic content restriction on guest WiFi). One new
table, additive only:

* ``content_filter_rules`` -- one row per blocked domain (DNS-sinkhole,
  see ``app.domains.network_config.renderers.render_content_filter_rule``)
  or blocked IP/CIDR (address-list + one shared firewall-filter DROP
  rule, see ``render_content_filter_enforcement``). A partial unique
  index (``uq_content_filter_rules_router_id_value_type_value``) enforces
  "a router may not hold two non-deleted rules for the same
  (value_type, value) pair" at the database level, mirroring migration
  ``0041``'s (``mac_authorization_entries``) identical partial-unique-
  index precedent.

See ``app.domains.content_filtering``'s own module docstring for the full,
honest RouterOS scope decision (DNS sinkhole + address-list/firewall-
filter, no Layer7, no web-proxy, no TLS interception).

No RBAC schema change beyond a brand-new, additive
``PermissionModule.CONTENT_FILTERING`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) plus additive ``AuditAction`` enum values
(``CONTENT_FILTER_RULE_CREATED``/``_UPDATED``/``_DELETED``) -- no
migration needed for any of those (``permission_groups``/``permissions``/
``permission_scopes``/``role_permissions`` rows are all seeded
idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0041``'s identical note).

Revision ID: 0080_create_content_filter_rules_table
Revises: 0079_add_snmp_device_metrics_monitoring
Create Date: 2026-08-09
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0080_create_content_filter_rules_table"
down_revision = "0079_add_snmp_device_metrics_monitoring"
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
        "content_filter_rules",
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
        sa.Column("category", sa.String(30), nullable=True),
        sa.Column("value_type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("content_filter_rules")
    op.create_index(
        "ix_content_filter_rules_router_id", "content_filter_rules", ["router_id"]
    )
    op.create_index(
        "ix_content_filter_rules_organization_id",
        "content_filter_rules",
        ["organization_id"],
    )
    op.create_index(
        "ix_content_filter_rules_location_id",
        "content_filter_rules",
        ["location_id"],
    )
    op.create_index(
        "ix_content_filter_rules_value_type",
        "content_filter_rules",
        ["value_type"],
    )
    op.create_index(
        "ix_content_filter_rules_is_enabled",
        "content_filter_rules",
        ["is_enabled"],
    )
    op.create_index(
        "uq_content_filter_rules_router_id_value_type_value",
        "content_filter_rules",
        ["router_id", "value_type", "value"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_content_filter_rules_router_id_value_type_value",
        table_name="content_filter_rules",
    )
    op.drop_index(
        "ix_content_filter_rules_is_enabled", table_name="content_filter_rules"
    )
    op.drop_index(
        "ix_content_filter_rules_value_type", table_name="content_filter_rules"
    )
    op.drop_index(
        "ix_content_filter_rules_location_id", table_name="content_filter_rules"
    )
    op.drop_index(
        "ix_content_filter_rules_organization_id", table_name="content_filter_rules"
    )
    op.drop_index(
        "ix_content_filter_rules_router_id", table_name="content_filter_rules"
    )
    _drop_base_model_indexes("content_filter_rules")
    op.drop_table("content_filter_rules")

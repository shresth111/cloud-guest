"""Router Readiness Checklist domain: ``router_checklist_items``.

New domain (``app.domains.readiness``), a per-router, fourteen-item
production-readiness checklist. One new table, additive only:

* ``router_checklist_items`` -- one row per ``(router_id, item_key)`` pair,
  updated in place on every re-check or manual confirmation. No history
  table -- a checklist reflects current state, mirroring
  ``app.domains.router_agent.models.RouterAgentCredential``'s own "one row
  per subject, updated in place" convention.

No RBAC schema change beyond a brand-new, additive
``PermissionModule.READINESS`` seeded module (``rbac/enums.py``/
``rbac/seed.py``) -- no migration needed for that (``permission_groups``/
``permissions``/``permission_scopes``/``role_permissions`` rows are all
seeded idempotently at application/CLI startup by ``seed_rbac``, never by a
migration, per this codebase's own established convention -- see e.g.
migration ``0046``'s identical note).

Revision ID: 0084_create_router_checklist_items_table
Revises: 0083_add_wan_routing_mode_and_link_weight
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0084_create_router_checklist_items_table"
down_revision = "0083_add_wan_routing_mode_and_link_weight"
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
        "router_checklist_items",
        *_base_model_columns(),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("item_key", sa.String(50), nullable=False),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="not_checked"
        ),
        sa.Column("detection_mode", sa.String(10), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "checked_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    _create_base_model_indexes("router_checklist_items")
    op.create_index(
        "ix_router_checklist_items_router_id", "router_checklist_items", ["router_id"]
    )
    op.create_index(
        "uq_router_checklist_items_router_id_item_key",
        "router_checklist_items",
        ["router_id", "item_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_router_checklist_items_router_id_item_key",
        table_name="router_checklist_items",
    )
    op.drop_index(
        "ix_router_checklist_items_router_id", table_name="router_checklist_items"
    )
    _drop_base_model_indexes("router_checklist_items")
    op.drop_table("router_checklist_items")

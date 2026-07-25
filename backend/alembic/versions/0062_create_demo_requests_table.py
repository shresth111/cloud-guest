"""Create Demo Request domain table: demo_requests.

Mirrors ``0058_create_support_tickets_table``'s conventions: the table gets
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Demo Requests is a brand-new domain: a prospective customer submits a
"Book a Demo" lead-capture form through a public, unauthenticated marketing
page/dialog; the Master console lists every submitted request and lets the
internal team update its status/internal notes.

``demo_requests`` -- one row per submitted lead. Unlike every tenant-scoped
domain (e.g. ``support_tickets``), there is deliberately **no**
``organization_id``/``created_by_user_id`` FK at all: the submitter is, by
definition, not yet a platform user or member of any organization (see
``app.domains.demo_request.models``'s own module docstring).

* ``full_name``/``email``/``company_name`` -- required ``String`` columns.
* ``phone`` -- nullable ``String(30)``.
* ``message`` -- nullable ``Text`` (what the prospect is looking for).
* ``status`` -- required ``String(20)``, server_default ``'new'``
  (new/contacted/scheduled/closed), indexed -- the field the Master console
  filters its queue by most often, mirroring
  ``support_tickets.status``'s identical indexing rationale.
* ``internal_notes`` -- nullable ``Text``, Master-console-only scratch pad.

No RBAC FK follow-up migration is needed (mirrors
``0058_create_support_tickets_table``'s own note): this table is not
referenced by any RBAC scope column (``PermissionModule.DEMO_REQUESTS`` is
seeded at ``ScopeType.GLOBAL``, no per-row scope column required).

Revision ID: 0062_create_demo_requests_table
Revises: 0061_fix_radius_nas_soft_delete_uniqueness
Create Date: 2026-07-25
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0062_create_demo_requests_table"
down_revision = "0061_fix_radius_nas_soft_delete_uniqueness"
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
        "demo_requests",
        *_base_model_columns(),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("phone", sa.String(30), nullable=True),
        sa.Column("company_name", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="new"),
        sa.Column("internal_notes", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("demo_requests")
    op.create_index("ix_demo_requests_status", "demo_requests", ["status"])
    op.create_index("ix_demo_requests_email", "demo_requests", ["email"])


def downgrade() -> None:
    op.drop_index("ix_demo_requests_email", table_name="demo_requests")
    op.drop_index("ix_demo_requests_status", table_name="demo_requests")
    _drop_base_model_indexes("demo_requests")
    op.drop_table("demo_requests")

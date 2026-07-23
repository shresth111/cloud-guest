"""Create Support Tickets domain table: support_tickets.

Mirrors ``0027_create_guest_access_tables``'s conventions: the table gets
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Support Tickets is a brand-new domain: customers (org members) raise a
support ticket from their dashboard; platform admins see every
organization's tickets on the Master dashboard and can update
status/assignment/resolution.

``support_tickets`` -- one row per ticket:

* ``organization_id`` -- required, FK -> organizations.id ON DELETE
  CASCADE, indexed. Every ticket belongs to exactly one organization.
* ``location_id`` -- nullable, FK -> locations.id ON DELETE CASCADE,
  indexed. ``NULL`` == an org-wide ticket, not about one specific location
  -- the same convention ``guest_access_rules.location_id`` (see
  ``0027_create_guest_access_tables``) already established.
* ``created_by_user_id`` -- required, FK -> users.id ON DELETE CASCADE,
  indexed. The user who raised the ticket.
* ``assigned_to_user_id`` -- nullable, FK -> users.id ON DELETE SET NULL,
  indexed. ``ON DELETE SET NULL`` (not CASCADE, unlike ``created_by_user_id``)
  since a ticket must survive its assignee's own account being deleted --
  it simply becomes unassigned again, whereas a ticket has no meaning
  without its creator.
* ``subject``/``description`` -- the ticket's own content.
* ``category`` -- nullable, free-form ``String(50)`` (e.g.
  "billing"/"technical"/"network"/"account"/"other"), no DB enum
  constraint -- application-level only, mirroring how
  ``guest_access_rules.rule_type`` is a plain ``String``, not a DB enum
  (see that migration's own docstring for why: adding a new value never
  requires an ``ALTER TYPE`` migration).
* ``priority`` -- required ``String(20)``, server_default ``'medium'``
  (low/medium/high/urgent), application-level validated only.
* ``status`` -- required ``String(20)``, server_default ``'open'``
  (open/in_progress/resolved/closed), indexed -- the field admins filter
  the Master dashboard's ticket queue by most often.
* ``resolution_notes``/``resolved_at`` -- nullable, populated once a
  platform admin resolves/closes the ticket (``resolved_at`` is
  application-set, not a DB trigger -- see
  ``app.domains.support_tickets.service`` for the auto-set/auto-clear
  logic on status transitions).

No RBAC FK follow-up migration is needed (mirrors
``0027_create_guest_access_tables``'s own note): this table is not
referenced by any RBAC scope column.

Revision ID: 0058_create_support_tickets_table
Revises: 0057_create_branding_table
Create Date: 2026-07-23
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0058_create_support_tickets_table"
down_revision = "0057_create_branding_table"
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
        "support_tickets",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_to_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(50), nullable=True),
        sa.Column(
            "priority", sa.String(20), nullable=False, server_default="medium"
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_support_tickets_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_support_tickets_location_id_locations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_support_tickets_created_by_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_user_id"],
            ["users.id"],
            name="fk_support_tickets_assigned_to_user_id_users",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("support_tickets")
    op.create_index(
        "ix_support_tickets_organization_id", "support_tickets", ["organization_id"]
    )
    op.create_index(
        "ix_support_tickets_location_id", "support_tickets", ["location_id"]
    )
    op.create_index(
        "ix_support_tickets_created_by_user_id",
        "support_tickets",
        ["created_by_user_id"],
    )
    op.create_index(
        "ix_support_tickets_assigned_to_user_id",
        "support_tickets",
        ["assigned_to_user_id"],
    )
    op.create_index("ix_support_tickets_status", "support_tickets", ["status"])


def downgrade() -> None:
    op.drop_index("ix_support_tickets_status", table_name="support_tickets")
    op.drop_index(
        "ix_support_tickets_assigned_to_user_id", table_name="support_tickets"
    )
    op.drop_index(
        "ix_support_tickets_created_by_user_id", table_name="support_tickets"
    )
    op.drop_index("ix_support_tickets_location_id", table_name="support_tickets")
    op.drop_index("ix_support_tickets_organization_id", table_name="support_tickets")
    _drop_base_model_indexes("support_tickets")
    op.drop_table("support_tickets")

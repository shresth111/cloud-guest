"""Create Support Tickets domain table: support_ticket_replies (BE-011-style
real-time reply thread, WebSocket + Redis pub/sub relay).

Mirrors ``0058_create_support_tickets_table``'s conventions: the table gets
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

``support_ticket_replies`` -- one row per reply message in a ticket's
thread:

* ``ticket_id`` -- required, FK -> support_tickets.id ON DELETE CASCADE,
  indexed. A reply has no meaning without its parent ticket.
* ``author_user_id`` -- required, FK -> users.id ON DELETE CASCADE,
  indexed. The customer (org member) or platform support agent who wrote
  this reply.
* ``message`` -- required ``Text``.
* ``is_staff_reply`` -- required ``Boolean``, no server default (always
  supplied explicitly by ``app.domains.support_tickets.service
  .TicketService.add_reply``): ``True`` for a platform-support reply from
  the Master console, ``False`` for the ticket-owning organization's own
  reply -- see ``app.domains.support_tickets.models.SupportTicketReply``'s
  own docstring for how this is derived.

No RBAC FK follow-up migration is needed (mirrors
``0058_create_support_tickets_table``'s own note): this table is not
referenced by any RBAC scope column.

Revision ID: 0060_create_support_ticket_replies_table
Revises: 0059_create_assistant_tables
Create Date: 2026-07-24
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0060_create_support_ticket_replies_table"
down_revision = "0059_create_assistant_tables"
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
        "support_ticket_replies",
        *_base_model_columns(),
        sa.Column("ticket_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("is_staff_reply", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["ticket_id"],
            ["support_tickets.id"],
            name="fk_support_ticket_replies_ticket_id_support_tickets",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["author_user_id"],
            ["users.id"],
            name="fk_support_ticket_replies_author_user_id_users",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("support_ticket_replies")
    op.create_index(
        "ix_support_ticket_replies_ticket_id",
        "support_ticket_replies",
        ["ticket_id"],
    )
    op.create_index(
        "ix_support_ticket_replies_author_user_id",
        "support_ticket_replies",
        ["author_user_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_support_ticket_replies_author_user_id",
        table_name="support_ticket_replies",
    )
    op.drop_index(
        "ix_support_ticket_replies_ticket_id", table_name="support_ticket_replies"
    )
    _drop_base_model_indexes("support_ticket_replies")
    op.drop_table("support_ticket_replies")

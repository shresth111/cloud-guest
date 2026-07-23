"""Create Assistant (customer support chatbot) domain tables:
assistant_conversations, assistant_messages.

Mirrors ``0058_create_support_tickets_table``'s conventions: each table
gets the ``BaseModel`` column set (id, created_at, updated_at,
soft-delete, audit, version) plus its own base-model indexes, using the
same ``_base_model_columns``/``_create_base_model_indexes`` helpers
(duplicated here, not imported -- Alembic migrations are meant to be
self-contained snapshots rather than depending on other migration
modules).

Assistant is a brand-new domain: a customer (org member) starts an AI
support-chat conversation from their own dashboard and exchanges
messages with it -- strictly self-service (see
``app.domains.assistant.service``'s own module docstring for why there
is no admin/cross-organization view here, unlike
``support_tickets``).

``assistant_conversations`` -- one row per chat thread:

* ``organization_id`` -- required, FK -> organizations.id ON DELETE
  CASCADE, indexed. Every conversation belongs to exactly one
  organization.
* ``user_id`` -- required, FK -> users.id ON DELETE CASCADE, indexed.
  The customer who owns this thread.
* ``title`` -- nullable ``String(255)``, auto-derived from the first
  message's own content (see
  ``app.domains.assistant.service._derive_title``) rather than required
  at creation.

``assistant_messages`` -- one row per message within a conversation:

* ``conversation_id`` -- required, FK -> assistant_conversations.id ON
  DELETE CASCADE, indexed. Deleting a conversation deletes its whole
  message history.
* ``role`` -- required ``String(20)`` ('user'/'assistant'), no DB enum
  constraint -- application-level only, mirroring how
  ``support_tickets.priority``/``.status`` are plain ``String`` columns
  (see that migration's own docstring for why: adding a new value never
  requires an ``ALTER TYPE`` migration).
* ``content`` -- required ``Text``.

No RBAC FK follow-up migration is needed (mirrors
``0058_create_support_tickets_table``'s own note): neither table is
referenced by any RBAC scope column. This domain reuses the RBAC
``ai_assistant`` permission module that already existed in
``app.domains.rbac.enums``/``app.domains.rbac.seed`` before this
migration (seeded, already assigned per-role grant levels) -- no RBAC
seed data change ships with this migration.

Revision ID: 0059_create_assistant_tables
Revises: 0058_create_support_tickets_table
Create Date: 2026-07-24
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0059_create_assistant_tables"
down_revision = "0058_create_support_tickets_table"
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
        "assistant_conversations",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_assistant_conversations_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_assistant_conversations_user_id_users",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("assistant_conversations")
    op.create_index(
        "ix_assistant_conversations_organization_id",
        "assistant_conversations",
        ["organization_id"],
    )
    op.create_index(
        "ix_assistant_conversations_user_id",
        "assistant_conversations",
        ["user_id"],
    )

    op.create_table(
        "assistant_messages",
        *_base_model_columns(),
        sa.Column("conversation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["assistant_conversations.id"],
            name="fk_assistant_messages_conversation_id_assistant_conversations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("assistant_messages")
    op.create_index(
        "ix_assistant_messages_conversation_id",
        "assistant_messages",
        ["conversation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_assistant_messages_conversation_id", table_name="assistant_messages"
    )
    _drop_base_model_indexes("assistant_messages")
    op.drop_table("assistant_messages")

    op.drop_index(
        "ix_assistant_conversations_user_id", table_name="assistant_conversations"
    )
    op.drop_index(
        "ix_assistant_conversations_organization_id",
        table_name="assistant_conversations",
    )
    _drop_base_model_indexes("assistant_conversations")
    op.drop_table("assistant_conversations")

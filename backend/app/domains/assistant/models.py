"""SQLAlchemy ORM models for the Assistant (customer support chatbot)
domain.

:class:`AssistantConversation` -- a customer (org member) support-chat
thread, self-service and self-scoped: a caller only ever sees/acts on
their own conversations (see ``service.py``), never another org member's,
even within the same organization -- unlike
``app.domains.support_tickets.models.SupportTicket``, which is visible
platform-wide to admins. ``organization_id`` is required (every
conversation belongs to exactly one organization, mirroring
``SupportTicket.organization_id``'s identical "not nullable" convention);
``user_id`` is required and is the customer who owns the thread.

:class:`AssistantMessage` -- one message (either the customer's or the
assistant's reply) within a conversation. ``conversation_id`` cascades on
delete: deleting a conversation deletes its whole message history, the
same "child rows have no meaning without their parent" posture
``app.domains.otp`` and others already establish for owned child tables.

Both extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version) for the same reason every other domain does
-- ``GenericRepository``/Alembic autogenerate/cross-domain FKs all keep
working uniformly, even though this domain's own service layer never
soft-deletes a conversation or message (there is no delete endpoint --
mirrors ``SupportTicket``'s own "no DELETE, closed not deleted" posture,
applied here as "no DELETE at all, a conversation just accumulates
history").
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class AssistantConversation(BaseModel):
    """A customer's own AI support-chat thread."""

    __tablename__ = "assistant_conversations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Nullable -- auto-set from the first message's own content (see
    # service.AssistantService._derive_title) rather than required at
    # creation, so a conversation can be started with no initial message
    # at all.
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_assistant_conversations_organization_id", "organization_id"),
        Index("ix_assistant_conversations_user_id", "user_id"),
    )

    def __repr__(self) -> str:
        return f"<AssistantConversation(id={self.id}, user_id={self.user_id})>"


class AssistantMessage(BaseModel):
    """One message -- customer or assistant -- within an
    :class:`AssistantConversation`."""

    __tablename__ = "assistant_messages"

    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assistant_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # 'user' or 'assistant' -- see constants.MessageRole. Plain String, not
    # a native enum -- see this module's own docstring.
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_assistant_messages_conversation_id", "conversation_id"),
    )

    def __repr__(self) -> str:
        return f"<AssistantMessage(id={self.id}, role={self.role})>"


__all__ = ["AssistantConversation", "AssistantMessage"]

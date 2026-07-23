"""Data access layer for the Assistant domain.

Mirrors ``app.domains.support_tickets.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``AssistantRepositoryProtocol``), and a concrete, ``GenericRepository``-
backed implementation (``AssistantRepository``) wrapping two
``GenericRepository`` instances (one per table), plus a hand-written
``select`` for the one thing ``GenericRepository`` can't express: listing
a conversation's messages in chronological order.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import AssistantConversation, AssistantMessage


class AssistantRepositoryProtocol(Protocol):
    async def create_conversation(self, **fields: object) -> AssistantConversation: ...

    async def get_conversation_by_id(
        self, conversation_id: uuid.UUID
    ) -> AssistantConversation | None: ...

    async def update_conversation(
        self, conversation: AssistantConversation, data: dict[str, object]
    ) -> AssistantConversation: ...

    async def list_conversations(
        self,
        *,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[AssistantConversation], PaginationMeta]: ...

    async def create_message(self, **fields: object) -> AssistantMessage: ...

    async def list_messages(
        self, conversation_id: uuid.UUID
    ) -> list[AssistantMessage]: ...


class AssistantRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``AssistantRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.conversations = GenericRepository(AssistantConversation, session)
        self.messages = GenericRepository(AssistantMessage, session)

    async def create_conversation(self, **fields: object) -> AssistantConversation:
        return await self.conversations.create(fields)

    async def get_conversation_by_id(
        self, conversation_id: uuid.UUID
    ) -> AssistantConversation | None:
        return await self.conversations.get_by_id(conversation_id)

    async def update_conversation(
        self, conversation: AssistantConversation, data: dict[str, object]
    ) -> AssistantConversation:
        return await self.conversations.update(conversation, data)

    async def list_conversations(
        self,
        *,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[AssistantConversation], PaginationMeta]:
        filters = [
            AssistantConversation.is_deleted.is_(False),
            AssistantConversation.organization_id == organization_id,
            AssistantConversation.user_id == user_id,
        ]
        statement = (
            select(AssistantConversation)
            .where(*filters)
            .order_by(AssistantConversation.updated_at.desc())
        )
        params = PageParams(page=page, page_size=page_size)
        result = await self.session.execute(paginate(statement, params))
        items = list(result.scalars().all())

        count_statement = (
            select(func.count()).select_from(AssistantConversation).where(*filters)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        return items, PaginationMeta.from_total(params, total_items)

    async def create_message(self, **fields: object) -> AssistantMessage:
        return await self.messages.create(fields)

    async def list_messages(self, conversation_id: uuid.UUID) -> list[AssistantMessage]:
        statement = (
            select(AssistantMessage)
            .where(
                AssistantMessage.conversation_id == conversation_id,
                AssistantMessage.is_deleted.is_(False),
            )
            .order_by(AssistantMessage.created_at.asc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = ["AssistantRepositoryProtocol", "AssistantRepository"]

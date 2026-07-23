"""Pydantic request/response schemas for the Assistant API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions --
see ``app.domains.support_tickets.schemas``) and is wrapped in the
project's standard ``ApiResponse``/``build_response`` envelope by
``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ConversationCreateRequest",
    "ConversationResponse",
    "ConversationStartResponse",
    "ConversationListResponse",
    "MessageCreateRequest",
    "MessageResponse",
    "MessageListResponse",
]


# ============================================================================
# Request schemas
# ============================================================================


class ConversationCreateRequest(BaseModel):
    initial_message: str | None = Field(
        default=None,
        min_length=1,
        max_length=4000,
        description=(
            "Optional first customer message. When present, the assistant's "
            "reply is generated and persisted immediately, and the "
            "conversation's title is auto-derived from it."
        ),
    )


class MessageCreateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000)


# ============================================================================
# Response schemas
# ============================================================================


class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    conversation_id: uuid.UUID
    role: str
    content: str
    created_at: datetime


class ConversationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID
    title: str | None
    created_at: datetime
    updated_at: datetime


class ConversationStartResponse(BaseModel):
    conversation: ConversationResponse
    # None only when the create request carried no initial_message.
    assistant_message: MessageResponse | None = None


class ConversationListResponse(BaseModel):
    items: list[ConversationResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class MessageListResponse(BaseModel):
    items: list[MessageResponse]

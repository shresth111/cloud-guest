"""Pydantic request/response schemas for the API Keys domain API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "ApiKeyCreateRequest",
    "ApiKeyCreateResponse",
    "ApiKeyResponse",
    "ApiKeyListResponse",
]


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    expires_at: datetime | None = None


class ApiKeyCreateResponse(BaseModel):
    """Returned exactly once, at creation -- ``plaintext_key`` is never
    recoverable again after this response."""

    id: str
    name: str
    plaintext_key: str
    display_prefix: str
    expires_at: datetime | None
    created_at: datetime


class ApiKeyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    display_prefix: str
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyListResponse(BaseModel):
    items: list[ApiKeyResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

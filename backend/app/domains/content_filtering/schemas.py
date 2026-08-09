"""Pydantic request/response schemas for the Content Filtering domain
API. Follows the same pydantic v2 conventions as
``app.domains.firewall.schemas``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.domains.auth.schemas import MessageResponse

from .constants import ContentFilterCategory, ContentFilterValueType

__all__ = [
    "MessageResponse",
    "ContentFilterRuleCreateRequest",
    "ContentFilterRuleUpdateRequest",
    "ContentFilterRuleResponse",
    "ContentFilterRuleListResponse",
]


class ContentFilterRuleCreateRequest(BaseModel):
    router_id: str
    name: str
    value_type: ContentFilterValueType
    value: str
    category: ContentFilterCategory | None = None
    comment: str | None = None
    is_enabled: bool = True


class ContentFilterRuleUpdateRequest(BaseModel):
    name: str | None = None
    value_type: ContentFilterValueType | None = None
    value: str | None = None
    category: ContentFilterCategory | None = None
    comment: str | None = None
    is_enabled: bool | None = None


class ContentFilterRuleResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    category: str | None
    value_type: str
    value: str
    comment: str | None
    is_enabled: bool
    created_at: datetime


class ContentFilterRuleListResponse(BaseModel):
    items: list[ContentFilterRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

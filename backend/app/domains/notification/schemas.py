"""Pydantic request/response schemas for the notification domain API.

Follows the same pydantic v2 conventions as ``app.domains.isp_routing.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "NotificationTemplateCreateRequest",
    "NotificationTemplateUpdateRequest",
    "NotificationTemplateResponse",
    "NotificationTemplateListResponse",
    "NotificationDeliveryResponse",
    "NotificationDeliveryListResponse",
]


class NotificationTemplateCreateRequest(BaseModel):
    event_type: str
    channel: str
    subject_template: str | None = None
    body_template: str = Field(min_length=1)
    is_active: bool = True


class NotificationTemplateUpdateRequest(BaseModel):
    subject_template: str | None = None
    body_template: str | None = Field(default=None, min_length=1)
    is_active: bool | None = None


class NotificationTemplateResponse(BaseModel):
    id: str
    organization_id: str | None
    event_type: str
    channel: str
    subject_template: str | None
    body_template: str
    is_active: bool
    created_at: datetime


class NotificationTemplateListResponse(BaseModel):
    items: list[NotificationTemplateResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class NotificationDeliveryResponse(BaseModel):
    id: str
    organization_id: str | None
    template_id: str | None
    event_type: str
    channel: str
    recipient: str
    subject: str | None
    status: str
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime | None
    sent_at: datetime | None
    error_message: str | None
    attachment_filename: str | None
    created_at: datetime


class NotificationDeliveryListResponse(BaseModel):
    items: list[NotificationDeliveryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

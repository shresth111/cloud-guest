"""Pydantic response schemas for the audit domain API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

__all__ = ["AuditLogEntryResponse", "AuditLogEntryListResponse"]


class AuditLogEntryResponse(BaseModel):
    id: str
    actor_user_id: str | None
    action: str
    entity_type: str
    entity_id: str | None
    description: str | None
    event_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "The structured detail the writing domain recorded alongside "
            "the description -- for a router update, "
            "{'changes': {'vendor': {'from': ..., 'to': ...}}}. "
            "Always an object; an entry whose writer recorded nothing "
            "serialises as {} rather than null, so a console can render it "
            "without a presence check."
        ),
    )
    organization_id: str | None
    location_id: str | None
    created_at: datetime


class AuditLogEntryListResponse(BaseModel):
    items: list[AuditLogEntryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

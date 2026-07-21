"""Pydantic response schemas for the audit domain API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

__all__ = ["AuditLogEntryResponse", "AuditLogEntryListResponse"]


class AuditLogEntryResponse(BaseModel):
    id: str
    actor_user_id: str | None
    action: str
    entity_type: str
    entity_id: str | None
    description: str | None
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

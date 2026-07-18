"""Pydantic schemas for the Events domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class EventCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    event_type: str
    category: str = Field(default="system")
    severity: str = Field(default="info")
    title: str = Field(min_length=1, max_length=200)
    description: str
    actor_id: uuid.UUID | None = None
    details: dict[str, Any] = Field(default_factory=dict)

class EventResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    event_type: str
    category: str
    severity: str
    title: str
    description: str
    actor_id: uuid.UUID | None = None
    details: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

"""Pydantic schemas for the Alerts domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class AlertResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    alert_type: str
    severity: str
    category: str
    status: str
    title: str
    description: str
    acknowledged_at: datetime | None = None
    acknowledged_by: uuid.UUID | None = None
    resolved_at: datetime | None = None
    resolved_by: uuid.UUID | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    metric: str
    condition: str
    threshold: float
    duration: int = Field(default=60, ge=10)
    severity: str = Field(default="warning")
    is_enabled: bool = Field(default=True)
    channels: dict[str, Any] = Field(default_factory=dict)

class AlertRuleResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    name: str
    metric: str
    condition: str
    threshold: float
    duration: int
    severity: str
    is_enabled: bool
    channels: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

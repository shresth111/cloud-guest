"""Pydantic schemas for the Reports domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class ReportCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    report_type: str
    file_format: str = Field(default="pdf")
    parameters: dict[str, Any] = Field(default_factory=dict)
    location_id: uuid.UUID | None = None

class ReportResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    name: str
    report_type: str
    file_format: str
    file_url: str | None = None
    status: str
    parameters: dict[str, Any]
    created_by: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ReportScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    report_type: str
    file_format: str = Field(default="pdf")
    frequency: str = Field(default="weekly")
    recipients: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    location_id: uuid.UUID | None = None

class ReportScheduleResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    name: str
    report_type: str
    file_format: str
    frequency: str
    recipients: list[str]
    parameters: dict[str, Any]
    is_active: bool
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    created_by: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

"""Pydantic request/response schemas for the Router Readiness Checklist
domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .constants import ChecklistCategory, ChecklistItemStatus, DetectionMode


class ChecklistItemResponse(BaseModel):
    item_key: str
    label: str
    description: str
    category: ChecklistCategory
    status: ChecklistItemStatus
    detection_mode: DetectionMode
    detail: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    last_checked_at: datetime | None = None
    checked_by_user_id: str | None = None


class ChecklistSummary(BaseModel):
    total: int
    passing: int
    failing: int
    not_checked: int


class ChecklistResponse(BaseModel):
    router_id: str
    summary: ChecklistSummary
    items: list[ChecklistItemResponse]


class ConfirmChecklistItemRequest(BaseModel):
    status: ChecklistItemStatus = Field(
        ...,
        description=(
            "Must be manually_confirmed or manually_failed -- this endpoint "
            "records a human decision, it does not re-run auto-detection."
        ),
    )
    detail: str | None = Field(default=None, max_length=500)


__all__ = [
    "ChecklistItemResponse",
    "ChecklistSummary",
    "ChecklistResponse",
    "ConfirmChecklistItemRequest",
]

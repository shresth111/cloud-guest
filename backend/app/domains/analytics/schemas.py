"""Pydantic request/response schemas for the Analytics API.

Follows this project's standard pydantic v2 conventions (``ConfigDict``,
``from_attributes``, explicit ``Field`` descriptions) and is wrapped in the
project's standard ``ApiResponse``/``build_response`` envelope by
``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnalyticsSnapshotResponse",
    "AnalyticsSnapshotListResponse",
    "TriggerAggregationRequest",
    "TriggerAggregationResponse",
]


class AnalyticsSnapshotResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    snapshot_type: str
    period_start: datetime
    period_end: datetime
    granularity: str
    metrics: dict[str, object]
    computed_at: datetime
    computation_duration_ms: float | None

    model_config = ConfigDict(from_attributes=True)


class AnalyticsSnapshotListResponse(BaseModel):
    items: list[AnalyticsSnapshotResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class TriggerAggregationRequest(BaseModel):
    organization_id: uuid.UUID = Field(
        description="Organization to (re)compute ORG_DAILY_SUMMARY plus "
        "every one of its active locations' LOCATION_DAILY_SUMMARY for."
    )
    target_date_iso: str | None = Field(
        default=None,
        description="ISO YYYY-MM-DD date to backfill; omit for today "
        "(a partial, still-open window).",
    )


class TriggerAggregationResponse(BaseModel):
    organization_id: uuid.UUID
    snapshots: list[AnalyticsSnapshotResponse] = Field(
        description="The ORG_DAILY_SUMMARY snapshot plus one "
        "LOCATION_DAILY_SUMMARY snapshot per active location."
    )

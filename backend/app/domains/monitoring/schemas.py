"""Pydantic request/response schemas for the Monitoring API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard ``ApiResponse``/
``build_response`` envelope by ``router.py``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "HealthCheckResponse",
    "ServiceHealthResponse",
    "DashboardSummaryResponse",
    "HealthHistoryResponse",
    "HealthCheckRunResponse",
    "TimelineEntryResponse",
    "EventTimelineResponse",
]


# ============================================================================
# Health Engine responses
# ============================================================================


class HealthCheckResponse(BaseModel):
    component: str
    status: str
    checked_at: datetime
    response_time_ms: float | None
    details: dict[str, object] | None
    error_message: str | None

    model_config = ConfigDict(from_attributes=True)


class ServiceHealthResponse(BaseModel):
    component: str
    status: str
    last_checked_at: datetime | None
    consecutive_failure_count: int
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DashboardSummaryResponse(BaseModel):
    overall_status: str
    components: list[ServiceHealthResponse]


class HealthHistoryResponse(BaseModel):
    items: list[HealthCheckResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class HealthCheckRunResponse(BaseModel):
    results: list[HealthCheckResponse]


# ============================================================================
# Event Engine responses
# ============================================================================


class TimelineEntryResponse(BaseModel):
    occurred_at: datetime
    category: str
    severity: str
    event_type: str
    source_domain: str
    message: str
    organization_id: str | None
    location_id: str | None
    router_id: str | None
    metadata: dict[str, object] = Field(default_factory=dict)


class EventTimelineResponse(BaseModel):
    items: list[TimelineEntryResponse]

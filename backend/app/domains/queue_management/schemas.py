"""Pydantic request/response schemas for the Queue Management Engine API.

Follows the same pydantic v2 conventions as
``app.domains.provisioning_engine.schemas``: plain ``str`` fields for every
UUID, explicit response-builder functions in ``router.py`` doing the
``str(...)`` conversion rather than ``ConfigDict(from_attributes=True)``
auto-mapping, and ``MessageResponse`` re-exported from the auth domain
rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "QueueProfileCreateRequest",
    "QueueProfileUpdateRequest",
    "QueueProfileResponse",
    "QueueProfileListResponse",
    "QueueScheduleCreateRequest",
    "QueueScheduleResponse",
    "QueueScheduleListResponse",
    "QueueTemplateCreateRequest",
    "QueueTemplateResponse",
    "QueueTemplateListResponse",
    "QueueAssignmentCreateRequest",
    "QueueAssignmentMoveRequest",
    "QueueAssignmentResponse",
    "QueueAssignmentListResponse",
    "QueueActionRequest",
]


# ============================================================================
# Queue profiles
# ============================================================================


class QueueProfileCreateRequest(BaseModel):
    name: str
    download_rate_kbps: int = Field(..., ge=0)
    upload_rate_kbps: int = Field(..., ge=0)
    description: str | None = None
    burst_download_kbps: int | None = Field(default=None, ge=0)
    burst_upload_kbps: int | None = Field(default=None, ge=0)
    burst_threshold_kbps: int | None = Field(default=None, ge=0)
    burst_time_seconds: int | None = Field(default=None, ge=0)
    priority: int = Field(default=8, ge=1, le=8)
    queue_type: str = "simple"
    is_system_profile: bool = False
    is_active: bool = True


class QueueProfileUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    download_rate_kbps: int | None = Field(default=None, ge=0)
    upload_rate_kbps: int | None = Field(default=None, ge=0)
    burst_download_kbps: int | None = Field(default=None, ge=0)
    burst_upload_kbps: int | None = Field(default=None, ge=0)
    burst_threshold_kbps: int | None = Field(default=None, ge=0)
    burst_time_seconds: int | None = Field(default=None, ge=0)
    priority: int | None = Field(default=None, ge=1, le=8)
    is_active: bool | None = None


class QueueProfileResponse(BaseModel):
    id: str
    organization_id: str | None
    name: str
    description: str | None
    download_rate_kbps: int
    upload_rate_kbps: int
    burst_download_kbps: int | None
    burst_upload_kbps: int | None
    burst_threshold_kbps: int | None
    burst_time_seconds: int | None
    priority: int
    queue_type: str
    is_system_profile: bool
    is_active: bool
    created_at: datetime


class QueueProfileListResponse(BaseModel):
    items: list[QueueProfileResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Queue schedules
# ============================================================================


class QueueScheduleCreateRequest(BaseModel):
    name: str
    schedule_type: str
    days_of_week: list[int] = Field(default_factory=list)
    start_time: str | None = None
    end_time: str | None = None
    specific_dates: list[str] = Field(default_factory=list)
    timezone: str = "UTC"
    is_active: bool = True


class QueueScheduleResponse(BaseModel):
    id: str
    organization_id: str | None
    name: str
    schedule_type: str
    days_of_week: list[Any]
    start_time: str | None
    end_time: str | None
    specific_dates: list[Any]
    timezone: str
    is_active: bool
    created_at: datetime


class QueueScheduleListResponse(BaseModel):
    items: list[QueueScheduleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Queue templates
# ============================================================================


class QueueTemplateCreateRequest(BaseModel):
    name: str
    persona: str
    description: str | None = None
    queue_profile_id: str | None = None
    default_queue_schedule_id: str | None = None
    is_active: bool = True


class QueueTemplateResponse(BaseModel):
    id: str
    organization_id: str | None
    name: str
    persona: str
    description: str | None
    queue_profile_id: str | None
    default_queue_schedule_id: str | None
    is_active: bool
    created_at: datetime


class QueueTemplateListResponse(BaseModel):
    items: list[QueueTemplateResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Queue assignments
# ============================================================================


class QueueAssignmentCreateRequest(BaseModel):
    target_type: str
    target_id: str | None = None
    router_id: str | None = None
    location_id: str | None = None
    device_target: str | None = None
    queue_profile_id: str | None = None
    queue_schedule_id: str | None = None
    priority_override: int | None = Field(default=None, ge=1, le=8)
    expires_at: datetime | None = None


class QueueAssignmentMoveRequest(BaseModel):
    new_queue_profile_id: str | None = None
    new_queue_schedule_id: str | None = None
    auto_apply: bool = True


class QueueAssignmentResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str | None
    router_id: str | None
    target_type: str
    target_id: str | None
    device_target: str | None
    device_queue_id: str | None
    queue_profile_id: str | None
    queue_schedule_id: str | None
    status: str
    priority_override: int | None
    applied_at: datetime | None
    expires_at: datetime | None
    error_message: str | None
    superseded_by_assignment_id: str | None
    created_at: datetime


class QueueAssignmentListResponse(BaseModel):
    items: list[QueueAssignmentResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class QueueActionRequest(BaseModel):
    """Body for ``POST /queue/apply``/``/remove``/``/reset`` -- all three
    act on one existing assignment by id."""

    assignment_id: str

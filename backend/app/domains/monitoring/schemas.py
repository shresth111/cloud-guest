"""Pydantic request/response schemas for the Monitoring API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard ``ApiResponse``/
``build_response`` envelope by ``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .constants import (
    AlertSeverity,
    AlertTriggerType,
    IncidentStatus,
    NotificationChannelType,
)

__all__ = [
    "HealthCheckResponse",
    "ServiceHealthResponse",
    "DashboardSummaryResponse",
    "HealthHistoryResponse",
    "HealthCheckRunResponse",
    "TimelineEntryResponse",
    "EventTimelineResponse",
    "AlertRuleCreateRequest",
    "AlertRuleUpdateRequest",
    "AlertRuleResponse",
    "AlertRuleListResponse",
    "AlertResponse",
    "AlertListResponse",
    "NotificationChannelCreateRequest",
    "NotificationChannelUpdateRequest",
    "NotificationChannelResponse",
    "NotificationChannelListResponse",
    "NotificationLogResponse",
    "NotificationLogListResponse",
    "IncidentCreateRequest",
    "IncidentUpdateRequest",
    "IncidentResponse",
    "IncidentListResponse",
    "IncidentAlertAttachRequest",
    "SlaTargetCreateRequest",
    "SlaTargetResponse",
    "SlaTargetWithLatestReportResponse",
    "SlaTargetListResponse",
    "SlaReportResponse",
    "SlaReportListResponse",
    "SlaReportGenerateRequest",
    "RouterLifecycleEntryResponse",
    "ZtpDashboardResponse",
    "ProvisioningFailureBreakdownResponse",
    "ProvisioningFailureSampleResponse",
    "RetryJobEntryResponse",
    "ZtpAnalyticsResponse",
    "PlatformDashboardResponse",
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


# ============================================================================
# Alert Engine
# ============================================================================


class AlertRuleCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    organization_id: uuid.UUID | None = None
    trigger_type: AlertTriggerType
    target_component: str | None = None
    condition_config: dict[str, object] = Field(default_factory=dict)
    severity: AlertSeverity
    is_active: bool = True
    notification_channel_ids: list[uuid.UUID] = Field(default_factory=list)


class AlertRuleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    trigger_type: AlertTriggerType | None = None
    target_component: str | None = None
    condition_config: dict[str, object] | None = None
    severity: AlertSeverity | None = None
    is_active: bool | None = None
    notification_channel_ids: list[uuid.UUID] | None = None


class AlertRuleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    organization_id: uuid.UUID | None
    trigger_type: str
    target_component: str | None
    condition_config: dict[str, object]
    severity: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertRuleListResponse(BaseModel):
    items: list[AlertRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class AlertResponse(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    status: str
    triggered_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by_user_id: uuid.UUID | None
    resolved_at: datetime | None
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    router_id: uuid.UUID | None
    message: str
    related_health_check_id: uuid.UUID | None
    related_event_id: uuid.UUID | None
    severity: str

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Notification Engine
# ============================================================================


class NotificationChannelCreateRequest(BaseModel):
    organization_id: uuid.UUID | None = None
    channel_type: NotificationChannelType
    name: str = Field(min_length=1, max_length=200)
    config: dict[str, object]
    is_active: bool = True


class NotificationChannelUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, object] | None = None
    is_active: bool | None = None


class NotificationChannelResponse(BaseModel):
    """Deliberately never includes decrypted ``config`` -- a channel's
    config may hold a Slack/Teams/Discord webhook URL or webhook auth
    header, a bearer-equivalent secret this API never echoes back in the
    clear, mirroring how ``app.domains.router``'s own API never returns a
    decrypted RouterOS API credential."""

    id: uuid.UUID
    organization_id: uuid.UUID | None
    channel_type: str
    name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NotificationChannelListResponse(BaseModel):
    items: list[NotificationChannelResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class NotificationLogResponse(BaseModel):
    id: uuid.UUID
    channel_id: uuid.UUID
    alert_id: uuid.UUID | None
    sent_at: datetime
    status: str
    error_message: str | None
    response_summary: str | None

    model_config = ConfigDict(from_attributes=True)


class NotificationLogListResponse(BaseModel):
    items: list[NotificationLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Incident Engine
# ============================================================================


class IncidentCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = None
    severity: AlertSeverity
    organization_id: uuid.UUID | None = None
    assigned_to_user_id: uuid.UUID | None = None


class IncidentUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    status: IncidentStatus | None = None
    assigned_to_user_id: uuid.UUID | None = None
    resolution_notes: str | None = None


class IncidentResponse(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    status: str
    severity: str
    organization_id: uuid.UUID | None
    assigned_to_user_id: uuid.UUID | None
    opened_at: datetime
    resolved_at: datetime | None
    closed_at: datetime | None
    resolution_notes: str | None

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    items: list[IncidentResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class IncidentAlertAttachRequest(BaseModel):
    alert_id: uuid.UUID


# ============================================================================
# SLA Monitoring
# ============================================================================


class SlaTargetCreateRequest(BaseModel):
    organization_id: uuid.UUID | None = None
    component: str | None = None
    target_percentage: float = Field(gt=0, le=100)
    measurement_window_days: int = Field(gt=0)


class SlaTargetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    component: str | None
    target_percentage: float
    measurement_window_days: int

    model_config = ConfigDict(from_attributes=True)


class SlaReportResponse(BaseModel):
    id: uuid.UUID
    sla_target_id: uuid.UUID
    period_start: datetime
    period_end: datetime
    achieved_percentage: float
    total_checks: int
    healthy_checks: int
    average_response_time_ms: float | None
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SlaTargetWithLatestReportResponse(BaseModel):
    target: SlaTargetResponse
    latest_report: SlaReportResponse | None


class SlaTargetListResponse(BaseModel):
    items: list[SlaTargetWithLatestReportResponse]


class SlaReportListResponse(BaseModel):
    items: list[SlaReportResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class SlaReportGenerateRequest(BaseModel):
    period_days: int | None = Field(default=None, gt=0)


# ============================================================================
# ZTP Monitoring Dashboard + Platform Dashboard Statistics (BE-011 Part 3)
# ============================================================================


class RouterLifecycleEntryResponse(BaseModel):
    router_id: uuid.UUID | None
    enrollment_id: uuid.UUID | None
    serial_number: str
    mac_address: str | None
    model: str
    name: str | None
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    router_status: str | None
    enrollment_status: str | None
    lifecycle_stage: str
    last_seen_at: datetime | None
    latest_job_type: str | None
    latest_job_status: str | None
    latest_job_attempts: int | None
    latest_job_max_attempts: int | None


class ZtpDashboardResponse(BaseModel):
    stage_counts: dict[str, int]
    pending_enrollment_count: int
    items: list[RouterLifecycleEntryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ProvisioningFailureBreakdownResponse(BaseModel):
    job_type: str
    failure_count: int


class ProvisioningFailureSampleResponse(BaseModel):
    job_id: uuid.UUID
    router_id: uuid.UUID
    job_type: str
    attempts: int
    max_attempts: int
    error_message: str | None
    scheduled_at: datetime


class RetryJobEntryResponse(BaseModel):
    job_id: uuid.UUID
    router_id: uuid.UUID
    job_type: str
    status: str
    attempts: int
    max_attempts: int
    attempts_remaining: int
    scheduled_at: datetime


class ZtpAnalyticsResponse(BaseModel):
    success_rate_percentage: float | None = Field(
        description=(
            "succeeded ProvisioningJobs / (succeeded + failed) ProvisioningJobs "
            "in the requested window -- see docs/monitoring/FLOW.md for the "
            "full denominator-choice write-up. null when zero terminal jobs "
            "exist in the window."
        )
    )
    succeeded_job_count: int
    terminal_job_count: int
    failure_breakdown: list[ProvisioningFailureBreakdownResponse]
    failure_samples: list[ProvisioningFailureSampleResponse]
    retry_jobs: list[RetryJobEntryResponse]
    average_activation_seconds: float | None = Field(
        description=(
            "Approximation: average(initial_config ProvisioningJob.completed_at "
            "- RouterEnrollmentRequest.reviewed_at). NOT a literal "
            "time-to-first-ONLINE measurement -- no table records that "
            "timestamp. See docs/monitoring/FLOW.md."
        )
    )
    activation_sample_size: int


class PlatformDashboardResponse(BaseModel):
    overall_health_status: str
    health_components: list[ServiceHealthResponse]
    alert_counts_by_severity: dict[str, int]
    alert_counts_by_status: dict[str, int]
    device_counts_by_status: dict[str, int]
    lifecycle_stage_counts: dict[str, int]
    pending_enrollment_count: int
    average_response_time_ms: float | None
    availability_percentage: float | None
    visitors: int | None
    unique_guests: int | None

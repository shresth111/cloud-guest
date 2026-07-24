"""Pydantic request/response schemas for the Provisioning Engine API.

Follows the same pydantic v2 conventions as
``app.domains.router_provisioning.schemas``: plain ``str`` fields for every
UUID (never a native ``UUID`` field type), explicit response-builder
functions in ``router.py`` doing the ``str(...)`` conversion rather than
``model_config = ConfigDict(from_attributes=True)`` auto-mapping, and
``MessageResponse`` re-exported from the auth domain rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "ProvisionJobCreateRequest",
    "ProvisionJobResponse",
    "ProvisionJobListResponse",
    "ProvisionCancelRequest",
    "ProvisionTimelineEntryResponse",
    "ProvisionTimelineResponse",
    "ProvisionDiscoverRequest",
    "DeviceDiscoveryResultResponse",
    "ProvisionValidateRequest",
    "ProvisionConfigurationRequest",
    "ProvisionConfigurationResponse",
    "ConsoleCommandRequest",
    "ConsoleCommandResponse",
]


# ============================================================================
# Jobs
# ============================================================================


class ProvisionJobCreateRequest(BaseModel):
    router_id: str
    provision_template_id: str | None = None
    max_retries: int = Field(default=3, ge=1, le=10)


class ProvisionJobResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str
    router_id: str
    provision_template_id: str | None
    status: str
    current_step: str | None
    progress_percent: int
    requested_by_user_id: str | None
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    retry_count: int
    max_retries: int
    retry_of_job_id: str | None
    is_rollback: bool
    rollback_of_job_id: str | None
    applied_config_version_id: str | None
    created_at: datetime


class ProvisionJobListResponse(BaseModel):
    items: list[ProvisionJobResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ProvisionCancelRequest(BaseModel):
    reason: str | None = None


# ============================================================================
# Timeline
# ============================================================================


class ProvisionTimelineEntryResponse(BaseModel):
    label: str
    occurred_at: datetime
    step_type: str | None
    status: str | None
    detail: str | None


class ProvisionTimelineResponse(BaseModel):
    job_id: str
    entries: list[ProvisionTimelineEntryResponse]


# ============================================================================
# Ad-hoc discover / validate / configuration preview
# ============================================================================


class ProvisionDiscoverRequest(BaseModel):
    router_id: str


class DeviceDiscoveryResultResponse(BaseModel):
    vendor: str
    model: str | None
    serial_number: str | None
    firmware_version: str | None
    cpu_load_percent: float | None
    free_memory_bytes: int | None
    total_memory_bytes: int | None
    uptime_seconds: int | None
    interfaces: list[str]
    mac_address: str | None


class ProvisionValidateRequest(BaseModel):
    router_id: str
    provision_template_id: str | None = None


class ProvisionConfigurationRequest(BaseModel):
    router_id: str
    provision_template_id: str


class ProvisionConfigurationResponse(BaseModel):
    rendered_content: str
    variables_used: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Raw device console (the Winbox-terminal-equivalent capability)
# ============================================================================


class ConsoleCommandRequest(BaseModel):
    router_id: str
    command: str = Field(min_length=1, max_length=4000)


class ConsoleCommandResponse(BaseModel):
    command: str
    stdout: str
    stderr: str
    exit_status: int

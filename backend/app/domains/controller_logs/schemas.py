"""Pydantic response schemas for the Controller Logs domain API.

Each of the six real log categories keeps its own real, specific fields
-- deliberately not forced into one generic, lossy "timestamp/level/
message" shape (see ``__init__.py``'s own module docstring: a
``ConfigVersion``'s ``version_number``/``status`` and a
``HealthCheck``'s ``response_time_ms`` are both real, useful fields a
unified shape would have to drop). Follows the same pydantic v2
conventions as ``app.domains.isp.schemas``: plain ``str`` fields for
every UUID, explicit response-builder functions in ``router.py`` doing
the ``str(...)`` conversion.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.common.masking import MaskedIdentifier

__all__ = [
    "ProvisionLogEntryResponse",
    "ProvisionLogListResponse",
    "ConfigVersionLogResponse",
    "ConfigVersionLogListResponse",
    "RouterEventLogResponse",
    "RouterEventLogListResponse",
    "LoginAttemptLogResponse",
    "LoginAttemptLogListResponse",
    "GuestLoginHistoryLogResponse",
    "GuestLoginHistoryLogListResponse",
    "HealthCheckLogResponse",
    "HealthCheckLogListResponse",
]


class ProvisionLogEntryResponse(BaseModel):
    id: str
    job_id: str
    step_id: str | None
    level: str
    message: str
    logged_at: datetime


class ProvisionLogListResponse(BaseModel):
    items: list[ProvisionLogEntryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ConfigVersionLogResponse(BaseModel):
    id: str
    router_id: str
    version_number: int
    status: str
    applied_at: datetime | None
    rollback_of_version_id: str | None
    is_backup: bool
    created_at: datetime


class ConfigVersionLogListResponse(BaseModel):
    items: list[ConfigVersionLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class RouterEventLogResponse(BaseModel):
    id: str
    router_id: str
    event_type: str
    message: str | None
    occurred_at: datetime
    metadata: dict[str, object]


class RouterEventLogListResponse(BaseModel):
    items: list[RouterEventLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class LoginAttemptLogResponse(BaseModel):
    id: str
    user_id: str | None
    email: str
    ip_address: str
    user_agent: str | None
    success: bool
    failure_reason: str | None
    created_at: datetime


class LoginAttemptLogListResponse(BaseModel):
    items: list[LoginAttemptLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class GuestLoginHistoryLogResponse(BaseModel):
    id: str
    guest_id: str | None
    organization_id: str | None
    location_id: str | None
    identifier: MaskedIdentifier
    auth_method: str
    success: bool
    failure_reason: str | None
    attempted_at: datetime
    ip_address: str | None


class GuestLoginHistoryLogListResponse(BaseModel):
    items: list[GuestLoginHistoryLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class HealthCheckLogResponse(BaseModel):
    id: str
    component: str
    status: str
    checked_at: datetime
    response_time_ms: float | None
    error_message: str | None


class HealthCheckLogListResponse(BaseModel):
    items: list[HealthCheckLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

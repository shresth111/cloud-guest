"""Pydantic request/response schemas for the Network Diagnostics domain
API.

Follows the same pydantic v2 conventions as ``app.domains.device_sync
.schemas``: plain ``str`` fields for every UUID, explicit
response-builder functions in ``router.py`` doing the ``str(...)``
conversion rather than ``ConfigDict(from_attributes=True)``
auto-mapping.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.network_diagnostics.constants import (
    DEFAULT_PING_COUNT,
    DEFAULT_PING_TIMEOUT_SECONDS,
    DEFAULT_TRACEROUTE_MAX_HOPS,
    DEFAULT_TRACEROUTE_TIMEOUT_SECONDS,
)

__all__ = [
    "PingRequest",
    "TracerouteRequest",
    "DiagnosticRunResponse",
    "DiagnosticRunListResponse",
]


class PingRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    count: int = Field(default=DEFAULT_PING_COUNT, ge=1, le=50)
    timeout_seconds: int = Field(default=DEFAULT_PING_TIMEOUT_SECONDS, ge=1, le=60)


class TracerouteRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    max_hops: int = Field(default=DEFAULT_TRACEROUTE_MAX_HOPS, ge=1, le=64)
    timeout_seconds: int = Field(
        default=DEFAULT_TRACEROUTE_TIMEOUT_SECONDS, ge=1, le=120
    )


class DiagnosticRunResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    diagnostic_type: str
    target: str
    status: str
    result: dict[str, object]
    error_message: str | None
    executed_by_user_id: str | None
    created_at: datetime


class DiagnosticRunListResponse(BaseModel):
    items: list[DiagnosticRunResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

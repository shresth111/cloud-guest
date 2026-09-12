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
    MAX_PING_COUNT,
    MAX_PING_TIMEOUT_SECONDS,
    MAX_TRACEROUTE_MAX_HOPS,
    MAX_TRACEROUTE_TIMEOUT_SECONDS,
)
from app.domains.network_diagnostics.validators import MAX_TARGET_LENGTH

__all__ = [
    "PingRequest",
    "TracerouteRequest",
    "DiagnosticRunResponse",
    "DiagnosticRunListResponse",
]


class PingRequest(BaseModel):
    """``target`` is only length-checked here; its real validation (and
    canonicalization) is ``validators.normalize_target``, called by the
    service so that the value persisted in the history is the normalized
    one and the rejection is this domain's own
    ``InvalidDiagnosticTargetError`` rather than a raw pydantic error.

    ``count`` and ``timeout_seconds`` are bounded well below their
    previous ceilings -- see ``constants.py``'s own write-up on why 50
    packets was a fifty-second request, and why ``timeout_seconds`` is now
    a real deadline rather than an accepted-and-discarded parameter."""

    target: str = Field(..., min_length=1, max_length=MAX_TARGET_LENGTH)
    count: int = Field(default=DEFAULT_PING_COUNT, ge=1, le=MAX_PING_COUNT)
    timeout_seconds: int = Field(
        default=DEFAULT_PING_TIMEOUT_SECONDS, ge=1, le=MAX_PING_TIMEOUT_SECONDS
    )


class TracerouteRequest(BaseModel):
    """See :class:`PingRequest` for the target/bounds write-up."""

    target: str = Field(..., min_length=1, max_length=MAX_TARGET_LENGTH)
    max_hops: int = Field(
        default=DEFAULT_TRACEROUTE_MAX_HOPS, ge=1, le=MAX_TRACEROUTE_MAX_HOPS
    )
    timeout_seconds: int = Field(
        default=DEFAULT_TRACEROUTE_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_TRACEROUTE_TIMEOUT_SECONDS,
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

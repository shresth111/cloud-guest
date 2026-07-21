"""Pydantic request/response schemas for the QoS & VOIP Priority domain
API.

Follows the same pydantic v2 conventions as ``app.domains.hotspot
.schemas``: plain ``str`` fields for every UUID, explicit
response-builder functions in ``router.py`` doing the ``str(...)``
conversion rather than ``ConfigDict(from_attributes=True)``
auto-mapping, and ``MessageResponse`` re-exported from the auth domain
rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse
from app.domains.qos.constants import DEFAULT_PRIORITY, MAX_PRIORITY, MIN_PRIORITY

__all__ = [
    "MessageResponse",
    "QosTrafficRuleCreateRequest",
    "QosTrafficRuleUpdateRequest",
    "QosTrafficRuleResponse",
    "QosTrafficRuleListResponse",
]


class QosTrafficRuleCreateRequest(BaseModel):
    router_id: str
    name: str
    protocol: str | None = None
    port_range_start: int | None = Field(default=None, ge=1, le=65535)
    port_range_end: int | None = Field(default=None, ge=1, le=65535)
    dscp_value: int | None = Field(default=None, ge=0, le=63)
    priority: int = Field(default=DEFAULT_PRIORITY, ge=MIN_PRIORITY, le=MAX_PRIORITY)
    is_enabled: bool = True


class QosTrafficRuleUpdateRequest(BaseModel):
    name: str | None = None
    protocol: str | None = None
    port_range_start: int | None = Field(default=None, ge=1, le=65535)
    port_range_end: int | None = Field(default=None, ge=1, le=65535)
    dscp_value: int | None = Field(default=None, ge=0, le=63)
    priority: int | None = Field(default=None, ge=MIN_PRIORITY, le=MAX_PRIORITY)
    is_enabled: bool | None = None


class QosTrafficRuleResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    protocol: str | None
    port_range_start: int | None
    port_range_end: int | None
    dscp_value: int | None
    priority: int
    is_enabled: bool
    created_at: datetime


class QosTrafficRuleListResponse(BaseModel):
    items: list[QosTrafficRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

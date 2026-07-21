"""Pydantic request/response schemas for the DHCP Pool Management domain
API.

Follows the same pydantic v2 conventions as ``app.domains.vlan.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse
from app.domains.dhcp.constants import DEFAULT_LEASE_TIME_SECONDS

__all__ = [
    "MessageResponse",
    "DhcpPoolCreateRequest",
    "DhcpPoolUpdateRequest",
    "DhcpPoolResponse",
    "DhcpPoolListResponse",
]


class DhcpPoolCreateRequest(BaseModel):
    router_id: str
    name: str
    address_range_start: str
    address_range_end: str
    interface: str | None = None
    gateway_ip_address: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    lease_time_seconds: int = Field(default=DEFAULT_LEASE_TIME_SECONDS, ge=1)
    is_enabled: bool = True


class DhcpPoolUpdateRequest(BaseModel):
    name: str | None = None
    address_range_start: str | None = None
    address_range_end: str | None = None
    interface: str | None = None
    gateway_ip_address: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    lease_time_seconds: int | None = Field(default=None, ge=1)
    is_enabled: bool | None = None


class DhcpPoolResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    interface: str | None
    address_range_start: str
    address_range_end: str
    gateway_ip_address: str | None
    dns_primary: str | None
    dns_secondary: str | None
    lease_time_seconds: int
    is_enabled: bool
    created_at: datetime


class DhcpPoolListResponse(BaseModel):
    items: list[DhcpPoolResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

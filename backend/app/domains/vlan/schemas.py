"""Pydantic request/response schemas for the VLAN Management domain API.

Follows the same pydantic v2 conventions as
``app.domains.isp_routing.schemas``: plain ``str`` fields for every UUID,
explicit response-builder functions in ``router.py`` doing the ``str(...)``
conversion rather than ``ConfigDict(from_attributes=True)`` auto-mapping,
and ``MessageResponse`` re-exported from the auth domain rather than
duplicated.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "VlanCreateRequest",
    "VlanUpdateRequest",
    "VlanResponse",
    "VlanListResponse",
]


class VlanCreateRequest(BaseModel):
    router_id: str
    vlan_id: int = Field(..., ge=1, le=4094)
    name: str
    gateway_ip_address: str | None = None
    cidr: str | None = None
    interface: str | None = None
    port_mode: Literal["trunk", "access"] = "trunk"
    enable_hotspot: bool = False
    description: str | None = None
    is_enabled: bool = True


class VlanUpdateRequest(BaseModel):
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    name: str | None = None
    gateway_ip_address: str | None = None
    cidr: str | None = None
    interface: str | None = None
    port_mode: Literal["trunk", "access"] | None = None
    enable_hotspot: bool | None = None
    description: str | None = None
    is_enabled: bool | None = None


class VlanResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    vlan_id: int
    name: str
    gateway_ip_address: str | None
    cidr: str | None
    interface: str | None
    port_mode: str
    enable_hotspot: bool
    description: str | None
    is_enabled: bool
    # Whether this row has ever reached a real router, and what happened.
    # Independent of is_enabled: a VLAN can be enabled for months and never
    # have been on a device, which was true of every row before this domain
    # had a push at all.
    device_push_status: str
    device_push_error: str | None
    device_pushed_at: datetime | None
    created_at: datetime


class VlanListResponse(BaseModel):
    items: list[VlanResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

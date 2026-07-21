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
    description: str | None = None
    is_enabled: bool = True


class VlanUpdateRequest(BaseModel):
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    name: str | None = None
    gateway_ip_address: str | None = None
    cidr: str | None = None
    interface: str | None = None
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
    description: str | None
    is_enabled: bool
    created_at: datetime


class VlanListResponse(BaseModel):
    items: list[VlanResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

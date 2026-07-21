"""Pydantic request/response schemas for the ISP Routing domain API.

Follows the same pydantic v2 conventions as ``app.domains.isp.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "IspRoutingRuleCreateRequest",
    "IspRoutingRuleUpdateRequest",
    "IspRoutingRuleResponse",
    "IspRoutingRuleListResponse",
]


class IspRoutingRuleCreateRequest(BaseModel):
    router_id: str
    isp_link_id: str
    rule_type: str
    name: str
    description: str | None = None
    priority: int = Field(default=0, ge=0)
    is_enabled: bool = True
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    source_mac_address: str | None = None
    ip_address: str | None = None
    source_cidr: str | None = None
    interface_name: str | None = None
    policy_id: str | None = None


class IspRoutingRuleUpdateRequest(BaseModel):
    isp_link_id: str | None = None
    rule_type: str | None = None
    name: str | None = None
    description: str | None = None
    priority: int | None = Field(default=None, ge=0)
    is_enabled: bool | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    source_mac_address: str | None = None
    ip_address: str | None = None
    source_cidr: str | None = None
    interface_name: str | None = None
    policy_id: str | None = None


class IspRoutingRuleResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    isp_link_id: str
    rule_type: str
    name: str
    description: str | None
    priority: int
    is_enabled: bool
    vlan_id: int | None
    source_mac_address: str | None
    ip_address: str | None
    source_cidr: str | None
    interface_name: str | None
    policy_id: str | None
    created_at: datetime


class IspRoutingRuleListResponse(BaseModel):
    items: list[IspRoutingRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

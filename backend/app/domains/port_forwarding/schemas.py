"""Pydantic request/response schemas for the Port Forwarding Management
domain API.

Follows the same pydantic v2 conventions as ``app.domains.dhcp.schemas``:
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
    "PortForwardingRuleCreateRequest",
    "PortForwardingRuleUpdateRequest",
    "PortForwardingRuleResponse",
    "PortForwardingRuleListResponse",
]


class PortForwardingRuleCreateRequest(BaseModel):
    router_id: str
    name: str
    protocol: str = "both"
    source_address: str | None = None
    destination_address: str | None = None
    destination_port: int = Field(..., ge=1, le=65535)
    internal_address: str
    internal_port: int = Field(..., ge=1, le=65535)
    description: str | None = None
    is_enabled: bool = True


class PortForwardingRuleUpdateRequest(BaseModel):
    name: str | None = None
    protocol: str | None = None
    source_address: str | None = None
    destination_address: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    internal_address: str | None = None
    internal_port: int | None = Field(default=None, ge=1, le=65535)
    description: str | None = None
    is_enabled: bool | None = None


class PortForwardingRuleResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    protocol: str
    source_address: str | None
    destination_address: str | None
    destination_port: int
    internal_address: str
    internal_port: int
    description: str | None
    is_enabled: bool
    created_at: datetime


class PortForwardingRuleListResponse(BaseModel):
    items: list[PortForwardingRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

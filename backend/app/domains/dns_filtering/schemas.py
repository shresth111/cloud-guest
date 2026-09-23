"""Request/response schemas for DNS filtering."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

__all__ = [
    "BypassHardeningRequest",
    "CategoryListResponse",
    "CategoryResponse",
    "LocationPolicyResponse",
    "OrganizationPolicyResponse",
    "PolicyUpdateRequest",
    "RouterFilteringStatusResponse",
]


class CategoryResponse(BaseModel):
    id: int
    name: str
    description: str
    category_class: str
    beta: bool
    is_security: bool
    subcategories: list[CategoryResponse] = Field(default_factory=list)


class CategoryListResponse(BaseModel):
    provider: str = "cloudflare_gateway"
    items: list[CategoryResponse]


class PolicyUpdateRequest(BaseModel):
    # Bounded: Cloudflare's catalogue is ~150 ids including subcategories.
    category_ids: list[int] = Field(default_factory=list, max_length=300)


class OrganizationPolicyResponse(BaseModel):
    organization_id: str
    category_ids: list[int]
    updated_at: datetime | None


class LocationPolicyResponse(BaseModel):
    location_id: str
    organization_id: str
    # What this venue actually blocks, and whether that is its own choice
    # ("location"), inherited from the organization default
    # ("organization"), or nothing at all ("none").
    effective_category_ids: list[int]
    source: str
    location_category_ids: list[int] | None
    organization_category_ids: list[int] | None


class RouterFilteringStatusResponse(BaseModel):
    router_id: str
    enabled: bool
    state: str
    device_push_status: str | None
    device_push_error: str | None
    device_pushed_at: datetime | None
    effective_category_ids: list[int]
    policy_source: str
    bypass_hardening_enabled: bool
    bypass_hardening_status: str
    bypass_hardening_error: str | None
    routeros_version: str | None
    # Honest limits, always shown with the status (PRD §10.2, §11.3).
    limitations: list[str]


class BypassHardeningRequest(BaseModel):
    enabled: bool

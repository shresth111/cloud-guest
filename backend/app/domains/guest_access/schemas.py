"""Pydantic request/response schemas for the Guest Access Control API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions) and
is wrapped in the project's standard ``ApiResponse``/``build_response``
envelope by ``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .constants import AccessRuleType

__all__ = [
    "GuestAccessRuleCreate",
    "DeviceAccessRuleCreate",
    "AccessCheckRequest",
    "GuestAccessRuleResponse",
    "DeviceAccessRuleResponse",
    "GuestAccessRuleListResponse",
    "DeviceAccessRuleListResponse",
    "AccessCheckResponse",
]


# ============================================================================
# Request schemas
# ============================================================================


class GuestAccessRuleCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(
        default=None,
        description="Scopes the rule to one location. Omit for org-wide.",
    )
    identifier: str = Field(..., min_length=1, max_length=255)
    rule_type: AccessRuleType
    reason: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "Required for rule_type=temporary. Optional (but permitted) for "
            "every other rule type."
        ),
    )


class DeviceAccessRuleCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(default=None)
    mac_address: str = Field(..., min_length=12, max_length=17)
    rule_type: AccessRuleType
    reason: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = Field(default=None)


class AccessCheckRequest(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = None
    identifier: str | None = Field(default=None, max_length=255)
    mac_address: str | None = Field(default=None, max_length=17)


# ============================================================================
# Response schemas
# ============================================================================


class GuestAccessRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    identifier: str
    rule_type: str
    reason: str | None
    expires_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class DeviceAccessRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    mac_address: str
    rule_type: str
    reason: str | None
    expires_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class GuestAccessRuleListResponse(BaseModel):
    items: list[GuestAccessRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class DeviceAccessRuleListResponse(BaseModel):
    items: list[DeviceAccessRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class AccessCheckResponse(BaseModel):
    allowed: bool
    rule_type: str | None
    matched_rule_id: uuid.UUID | None
    reason: str | None

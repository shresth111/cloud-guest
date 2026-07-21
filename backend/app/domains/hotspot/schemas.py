"""Pydantic request/response schemas for the Hotspot Settings domain API.

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
from app.domains.hotspot.constants import MAX_WALLED_GARDEN_HOSTS

__all__ = [
    "MessageResponse",
    "HotspotProfileCreateRequest",
    "HotspotProfileUpdateRequest",
    "HotspotProfileResponse",
    "HotspotProfileListResponse",
]


class HotspotProfileCreateRequest(BaseModel):
    router_id: str
    name: str
    session_timeout_minutes: int | None = Field(default=None, ge=1)
    idle_timeout_minutes: int | None = Field(default=None, ge=1)
    upload_limit_kbps: int | None = Field(default=None, ge=1)
    download_limit_kbps: int | None = Field(default=None, ge=1)
    walled_garden_hosts: list[str] = Field(
        default_factory=list, max_length=MAX_WALLED_GARDEN_HOSTS
    )
    is_enabled: bool = True


class HotspotProfileUpdateRequest(BaseModel):
    name: str | None = None
    session_timeout_minutes: int | None = Field(default=None, ge=1)
    idle_timeout_minutes: int | None = Field(default=None, ge=1)
    upload_limit_kbps: int | None = Field(default=None, ge=1)
    download_limit_kbps: int | None = Field(default=None, ge=1)
    walled_garden_hosts: list[str] | None = Field(
        default=None, max_length=MAX_WALLED_GARDEN_HOSTS
    )
    is_enabled: bool | None = None


class HotspotProfileResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    session_timeout_minutes: int | None
    idle_timeout_minutes: int | None
    upload_limit_kbps: int | None
    download_limit_kbps: int | None
    walled_garden_hosts: list[str]
    is_enabled: bool
    created_at: datetime


class HotspotProfileListResponse(BaseModel):
    items: list[HotspotProfileResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

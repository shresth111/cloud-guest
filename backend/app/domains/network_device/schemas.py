"""Pydantic request/response schemas for the Network Device (NAC) domain
API. Follows the same pydantic v2 conventions as ``app.domains.dhcp.schemas``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.domains.auth.schemas import MessageResponse

from .constants import ComplianceStatus

__all__ = [
    "MessageResponse",
    "NetworkDeviceRegisterRequest",
    "NetworkDeviceUpdateRequest",
    "NetworkDeviceComplianceStatusRequest",
    "NetworkDeviceResponse",
    "NetworkDeviceListResponse",
]


class NetworkDeviceRegisterRequest(BaseModel):
    location_id: str
    router_id: str | None = None
    mac_address: str
    vendor: str | None = None
    device_type: str | None = None
    comment: str | None = None
    is_active: bool = True


class NetworkDeviceUpdateRequest(BaseModel):
    router_id: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    comment: str | None = None
    is_active: bool | None = None


class NetworkDeviceComplianceStatusRequest(BaseModel):
    compliance_status: ComplianceStatus
    compliance_notes: str | None = None


class NetworkDeviceResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str
    router_id: str | None
    mac_address: str
    vendor: str | None
    device_type: str | None
    compliance_status: str
    compliance_notes: str | None
    last_reviewed_at: datetime | None
    comment: str | None
    is_active: bool
    created_at: datetime


class NetworkDeviceListResponse(BaseModel):
    items: list[NetworkDeviceResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

"""Pydantic request/response schemas for the ISP Management domain API.

Follows the same pydantic v2 conventions as
``app.domains.queue_management.schemas``: plain ``str`` fields for every
UUID, explicit response-builder functions in ``router.py`` doing the
``str(...)`` conversion rather than ``ConfigDict(from_attributes=True)``
auto-mapping, and ``MessageResponse`` re-exported from the auth domain
rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "IspLinkCreateRequest",
    "IspLinkUpdateRequest",
    "IspLinkResponse",
    "IspLinkListResponse",
    "IspHealthCheckResponse",
    "IspHealthCheckListResponse",
    "IspFailoverRequest",
]


# ============================================================================
# ISP links
# ============================================================================


class IspLinkCreateRequest(BaseModel):
    router_id: str
    provider_name: str
    link_type: str = "other"
    role: str
    priority: int = Field(default=0, ge=0)
    interface: str | None = None
    gateway_ip_address: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    download_bandwidth_mbps: int | None = Field(default=None, ge=0)
    upload_bandwidth_mbps: int | None = Field(default=None, ge=0)
    auto_failback: bool = True


class IspLinkUpdateRequest(BaseModel):
    provider_name: str | None = None
    link_type: str | None = None
    role: str | None = None
    priority: int | None = Field(default=None, ge=0)
    interface: str | None = None
    gateway_ip_address: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    download_bandwidth_mbps: int | None = Field(default=None, ge=0)
    upload_bandwidth_mbps: int | None = Field(default=None, ge=0)
    auto_failback: bool | None = None
    is_enabled: bool | None = None


class IspLinkResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    provider_name: str
    link_type: str
    role: str
    is_active_uplink: bool
    auto_failback: bool
    is_enabled: bool
    priority: int
    interface: str | None
    gateway_ip_address: str | None
    dns_primary: str | None
    dns_secondary: str | None
    download_bandwidth_mbps: int | None
    upload_bandwidth_mbps: int | None
    health_status: str
    latency_ms: float | None
    packet_loss_percentage: float | None
    last_checked_at: datetime | None
    consecutive_unhealthy_count: int
    created_at: datetime


class IspLinkListResponse(BaseModel):
    items: list[IspLinkResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Health checks (history)
# ============================================================================


class IspHealthCheckResponse(BaseModel):
    id: str
    isp_link_id: str
    checked_at: datetime
    status: str
    latency_ms: float | None
    packet_loss_percentage: float | None
    error_message: str | None


class IspHealthCheckListResponse(BaseModel):
    items: list[IspHealthCheckResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
    availability_percentage: float | None


# ============================================================================
# Failover / failback
# ============================================================================


class IspFailoverRequest(BaseModel):
    reason: str = "manual_admin_trigger"

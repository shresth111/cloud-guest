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
from typing import Literal

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
    "IspLinkManualStatusRequest",
]


# ============================================================================
# ISP links
# ============================================================================


class IspLinkCreateRequest(BaseModel):
    router_id: str
    provider_name: str
    link_type: str = "other"
    # How this link's own gateway/IP is actually obtained -- drives which
    # real health-check strategy IspService.ping_link uses. Orthogonal to
    # link_type (physical medium): see constants.IspConnectionMode's own
    # docstring for why these are deliberately separate fields.
    connection_mode: Literal["static", "dhcp", "pppoe"] = "static"
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
    connection_mode: Literal["static", "dhcp", "pppoe"] | None = None
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
    connection_mode: str
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
    health_status_source: str
    # "Down since" -- a computed read-model (IspService
    # .compute_unhealthy_since), never a stored column. Non-null only
    # when health_status is currently "unhealthy".
    unhealthy_since: datetime | None
    latency_ms: float | None
    packet_loss_percentage: float | None
    # Live traffic load -- the most recently *computed* rate, distinct
    # from download_bandwidth_mbps/upload_bandwidth_mbps above (the
    # link's provisioned plan capacity, never measured). Null until the
    # second successful sample ever (a rate needs two readings) -- see
    # IspService.sample_link_traffic's own docstring.
    current_download_mbps: float | None
    current_upload_mbps: float | None
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
    source: str
    latency_ms: float | None
    packet_loss_percentage: float | None
    error_message: str | None
    # Real traffic-load reading for this same tick -- null whenever a
    # rate genuinely couldn't be computed (see IspLink
    # .current_download_mbps's own comment). This is what the "Traffic
    # Load" graph renders from -- the exact same rows the up/down
    # "Status Timeline" already uses.
    download_mbps: float | None
    upload_mbps: float | None


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


# ============================================================================
# Manual status override -- the "Internet Connection" view's one real
# write. Never pushes anything to the router itself; see
# ``IspService.set_manual_health_status``.
# ============================================================================


class IspLinkManualStatusRequest(BaseModel):
    """Restricted to the two values "up"/"down" actually maps onto
    (``constants.HealthStatus.HEALTHY``/``UNHEALTHY``) -- deliberately
    never ``degraded``/``unknown`` here: an admin overriding a link's
    status is making a binary "it's up" / "it's down" call, not
    classifying a nuanced reading the way a real ping measurement can."""

    health_status: Literal["healthy", "unhealthy"]
    reason: str | None = Field(default=None, max_length=500)

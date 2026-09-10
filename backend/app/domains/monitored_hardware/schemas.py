"""Pydantic request/response schemas for the Monitored Hardware domain
API. Follows the same pydantic v2 conventions as
``app.domains.network_device.schemas``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "MonitoredHardwareRegisterRequest",
    "MonitoredHardwareResponse",
    "MonitoredHardwareListResponse",
]


class MonitoredHardwareRegisterRequest(BaseModel):
    location_id: str
    router_id: str | None = None
    name: str
    mac_address: str
    device_type: str
    floor: str | None = None


class MonitoredHardwareResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str
    router_id: str | None
    name: str
    mac_address: str
    device_type: str
    floor: str | None
    # "up" / "down" / "unknown" -- see the domain's own module docstring
    # for exactly how this is derived (never fabricated).
    status: str
    last_seen_at: datetime | None
    # When the device was first observed on this network *and has stayed
    # on since* -- the sync sweep preserves it across ticks for an active
    # device, so for a "up" row it answers "how long has it been up?",
    # which ``last_seen_at`` (the age of the sync sweep's own view)
    # cannot. Null for "down"/"unknown"/never-observed rows -- never
    # fabricated from ``last_seen_at``.
    connected_at: datetime | None
    created_at: datetime


class MonitoredHardwareListResponse(BaseModel):
    items: list[MonitoredHardwareResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

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
    # Real DEVICE uptime -- "this box has not rebooted in N seconds" -- and
    # emphatically NOT the same fact as ``last_seen_at`` above, which only
    # says "we heard from it recently". A device that reboots every twenty
    # minutes has a perfectly healthy ``last_seen_at`` the whole time.
    #
    # Populated only where a real source exists: the hardware row's MAC
    # matches a ``Router`` this platform manages, whose own RouterOS-API/
    # SNMP health sweeps already read ``/system/resource`` uptime every
    # 600s/300s into ``router_health_snapshots``. This is a plain read of
    # that existing table -- never a new poll, and never a device reached
    # at request time.
    #
    # ``None`` for every other row, and that is the honest answer, not a
    # gap to be filled: there is no mechanism anywhere in this platform
    # that can learn a third-party access point's, printer's or camera's
    # uptime, so the alternative to ``None`` is a fabricated number. Same
    # posture as ``HardwareStatus.UNKNOWN``.
    uptime_seconds: int | None
    # When the reading above was actually taken. A 7-hour uptime read
    # forty minutes ago is not a 7-hour uptime now, and a caller that
    # renders the number without this cannot tell a live value from one
    # left behind by a sweep that has since stopped running. ``None``
    # exactly when ``uptime_seconds`` is.
    uptime_recorded_at: datetime | None
    created_at: datetime


class MonitoredHardwareListResponse(BaseModel):
    items: list[MonitoredHardwareResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

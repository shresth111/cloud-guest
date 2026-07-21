"""Pydantic request/response schemas for the Connected Device Management
domain API.

Follows the same pydantic v2 conventions as ``app.domains.isp.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.

There is no "create a connected device" request schema -- devices only
ever come into existence via a real sync (see ``service.py``'s own
module docstring); the only user-editable field is ``comment``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "ConnectedDeviceResponse",
    "ConnectedDeviceListResponse",
    "ConnectedDeviceCommentRequest",
    "ConnectedDeviceAccessActionRequest",
    "DeviceSyncSummaryResponse",
]


class ConnectedDeviceResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    mac_address: str
    ip_address: str | None
    hostname: str | None
    vendor: str | None
    connection_type: str
    interface: str | None
    signal_strength_dbm: int | None
    is_active: bool
    connected_at: datetime | None
    last_seen_at: datetime | None
    comment: str | None
    guest_id: str | None
    guest_session_id: str | None
    created_at: datetime


class ConnectedDeviceListResponse(BaseModel):
    items: list[ConnectedDeviceResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ConnectedDeviceCommentRequest(BaseModel):
    comment: str


class ConnectedDeviceAccessActionRequest(BaseModel):
    reason: str | None = None


class DeviceSyncSummaryResponse(BaseModel):
    discovered: int
    updated: int
    disconnected: int

"""Wire shapes for Aruba Instant On multi-AP (``aruba_access_points``)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ArubaAccessPointCreateRequest",
    "ArubaAccessPointRecord",
    "ArubaAccessPointRegistryResponse",
    "ArubaAccessPointUpdateRequest",
    "LocationAccessPointItem",
    "LocationAccessPointsResponse",
]


# -- Master (GLOBAL) ---------------------------------------------------------


class ArubaAccessPointRecord(BaseModel):
    """One registry row as Master sees it. ``id`` is null only for the
    synthesized primary row of a router whose own MAC has no table row."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID | None = None
    router_id: uuid.UUID
    mac: str
    name: str | None = None
    serial: str | None = None
    model: str | None = None
    source: str
    status: str
    is_primary: bool = False
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class ArubaAccessPointRegistryResponse(BaseModel):
    router_id: uuid.UUID
    items: list[ArubaAccessPointRecord]


class ArubaAccessPointCreateRequest(BaseModel):
    """Master manual add. Approved on creation. No organization or location:
    both are copied from the router."""

    model_config = ConfigDict(extra="forbid")

    mac: str = Field(..., min_length=12, max_length=32)
    name: str | None = Field(default=None, max_length=255)


class ArubaAccessPointUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["approved", "rejected"] | None = None
    name: str | None = Field(default=None, max_length=255)


# -- Customer (ORGANIZATION, location-keyed) ---------------------------------


class LocationAccessPointItem(BaseModel):
    """One approved AP of the venue, with what RADIUS accounting says about
    it. Every count is computed from this platform's own ``guest_sessions``
    (``ap_mac``), never estimated.

    ``status``: ``online`` when this AP sent accounting (or was seen in a
    RADIUS packet) within ``online_window_seconds``, or Instant On reports
    it up; otherwise ``no_recent_activity`` -- an AP with no guests sends
    nothing, so silence is not "offline". ``status_source`` says which.
    ``instant_on_status`` is set only when Instant On data is enabled for
    this venue and current."""

    id: uuid.UUID | None = None
    name: str | None = None
    mac: str
    model: str | None = None
    serial: str | None = None
    is_primary: bool = False
    clients_now: int
    sessions_today: int
    download_bytes_today: int
    upload_bytes_today: int
    last_seen_at: datetime | None = None
    status: Literal["online", "no_recent_activity"]
    status_source: Literal["radius", "instant_on"] | None = None
    instant_on_status: str | None = None


class LocationAccessPointsResponse(BaseModel):
    """``applicable`` is false for a location with no Aruba Instant On
    device (every MikroTik / Omada venue, and another tenant's location):
    ``items`` is then empty and nothing else is meaningful.

    ``unattributed_clients_now``: guests online whose sessions carry no AP
    (accounted before AP tracking existed); they are in no AP's count.

    "Today" starts at ``day_start`` (local midnight for
    ``tz_offset_minutes``). ``*_bytes_today`` sums sessions that started
    today or are still active -- RADIUS reports per-session totals, not
    per-day ones."""

    location_id: uuid.UUID
    applicable: bool
    as_of: datetime
    day_start: datetime
    online_window_seconds: int
    unattributed_clients_now: int
    items: list[LocationAccessPointItem]

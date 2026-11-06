"""Response schemas for the customer dashboard's venue-insight endpoints
(``GET /analytics/venue-insights/*``). See ``venue_insights.py`` for what
each number means and why some funnel stages are reported as unavailable
rather than estimated."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class PeakHourCell(BaseModel):
    #: ISO weekday in the venue's timezone: 1 = Monday ... 7 = Sunday.
    weekday: int
    #: Hour of day in the venue's timezone, 0-23.
    hour: int
    sessions: int
    guests: int


class PeakHoursResponse(BaseModel):
    location_id: uuid.UUID
    timezone: str
    window_start: str
    window_end: str
    total_sessions: int
    #: Only cells with at least one session; absent cells are zero.
    cells: list[PeakHourCell]


class GuestMixResponse(BaseModel):
    location_id: uuid.UUID
    timezone: str
    window_start: str
    window_end: str
    unique_guests: int
    new_guests: int
    returning_guests: int
    sessions: int
    #: Guests who came on two or more different local calendar days inside
    #: the window.
    multi_visit_guests: int
    repeat_visit_rate_percent: float | None
    #: Earliest session this platform holds for the location. Guests who
    #: visited before this date are invisible to "returning".
    history_starts_at: str | None
    #: False when no session predates the window, so every guest in it is
    #: necessarily counted as new.
    has_prior_history: bool


class FunnelStageUnavailable(BaseModel):
    """A stage this venue cannot report. ``message`` says why, per venue."""

    available: Literal[False] = False
    message: str


class PortalOpenedStage(BaseModel):
    """``portal_impressions`` in the window. ``count`` is page loads with one
    device's reloads inside ten minutes collapsed into one; ``devices`` is
    distinct devices among loads that carried a MAC (a load without one is
    in ``count`` only)."""

    available: Literal[True] = True
    count: int
    devices: int
    #: Earliest impression this platform holds for the venue, or None when
    #: there is none yet. A window starting before it is only partly counted.
    tracked_since: str | None


class InternetConfirmedStage(BaseModel):
    """Sessions whose ``internet_confirmed_at`` falls in the window -- the
    NAS or controller itself reported the device through."""

    available: Literal[True] = True
    #: Distinct guests, every login method.
    count: int
    #: Distinct guests on an OTP-method session: the number to set against
    #: ``otp_signed_in_guests``.
    otp_guests: int
    sessions: int
    tracked_since: str | None
    #: Set when some of the venue's routers cannot report this stage, so the
    #: count can be lower than reality.
    note: str | None = None


PortalOpened = Annotated[
    PortalOpenedStage | FunnelStageUnavailable, Field(discriminator="available")
]
InternetConfirmed = Annotated[
    InternetConfirmedStage | FunnelStageUnavailable, Field(discriminator="available")
]


class LoginMethodItem(BaseModel):
    auth_method: str
    successful_logins: int
    failed_logins: int
    guests: int


class LoginFunnelResponse(BaseModel):
    location_id: uuid.UUID
    window_start: str
    window_end: str
    #: Rows in ``otp_requests`` (resends included).
    otp_codes_sent: int
    #: Distinct phone numbers / emails that asked for a code.
    otp_requested_guests: int
    #: Distinct identifiers whose code was verified.
    otp_verified_guests: int
    #: Distinct identifiers with a successful OTP login recorded, i.e. a
    #: guest session was issued.
    otp_signed_in_guests: int
    portal_opened: PortalOpened
    internet_confirmed: InternetConfirmed
    methods: list[LoginMethodItem]


class LocationComparisonItem(BaseModel):
    location_id: uuid.UUID
    location_name: str
    guests: int
    sessions: int
    routers_total: int
    routers_online: int
    last_router_seen_at: str | None


class LocationComparisonResponse(BaseModel):
    organization_id: uuid.UUID
    window_start: str
    window_end: str
    liveness_note: str = (
        "routers_online is the router's status right now (online and a "
        "heartbeat within the offline threshold), not uptime over the window."
    )
    locations: list[LocationComparisonItem]


__all__ = [
    "FunnelStageUnavailable",
    "InternetConfirmedStage",
    "PortalOpenedStage",
    "GuestMixResponse",
    "LocationComparisonItem",
    "LocationComparisonResponse",
    "LoginFunnelResponse",
    "LoginMethodItem",
    "PeakHourCell",
    "PeakHoursResponse",
]

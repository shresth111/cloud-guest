"""Response schemas for the customer dashboard's venue-insight endpoints
(``GET /analytics/venue-insights/*``). See ``venue_insights.py`` for what
each number means and why some funnel stages are reported as unavailable
rather than estimated."""

from __future__ import annotations

import uuid

from pydantic import BaseModel


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
    available: bool = False
    message: str


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
    portal_opened: FunnelStageUnavailable
    internet_confirmed: FunnelStageUnavailable
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
    "GuestMixResponse",
    "LocationComparisonItem",
    "LocationComparisonResponse",
    "LoginFunnelResponse",
    "LoginMethodItem",
    "PeakHourCell",
    "PeakHoursResponse",
]

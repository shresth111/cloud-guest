"""One guest session's device events, for the customer's Guest Connection
Records.

The caller hands in a session it has *already* fetched through the guest
domain's own scoped getter (``GuestService.get_session``: organization +
caller location scope). Everything here is then keyed on that row's
organization, venue, router, device MAC and IP -- never on anything from the
request -- so this module cannot widen what the caller may see.

Matching rule (the same discipline as the NetFlow talker matcher: exactly
one session or nothing, never the nearest one):

1. Key + window. An event that carries a MAC (DHCP) matches on the MAC,
   from ``GUEST_EVENT_LEAD_MINUTES`` before the session started to
   ``GUEST_EVENT_TRAIL_MINUTES`` after it ended. An event without one
   (hotspot sign-in/out) matches on IP, only on the session's own router
   (two routers at one venue may hand out the same private range), and only
   within ``GUEST_EVENT_IP_SKEW_MINUTES`` of the session -- an IP is reused
   by the next guest within minutes. A session with no end is open until
   now while ``active``/``paused``; otherwise it ends at its last recorded
   activity (a stale row must not claim every later event).
2. Same organization and venue, always.
3. The event is shown only if it matches **exactly one** session -- this
   one. If any other session (any guest) also matches it, it is ambiguous
   and is not shown; the response says how many were held back.

Honest coverage states, so an empty list never reads as "nothing happened":

* ``not_sending`` -- no router at this venue has ever sent device logs.
* ``not_sending_during_session`` -- it started sending after this session.
* ``covered`` -- logs were arriving; ``events`` may still be empty.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from app.domains.guest.constants import GuestSessionStatus

from .constants import (
    GUEST_EVENT_IP_SKEW_MINUTES,
    GUEST_EVENT_LEAD_MINUTES,
    GUEST_EVENT_TRAIL_MINUTES,
    MAX_SESSION_DEVICE_EVENTS,
)
from .repository import DeviceLogsRepository, SessionMatchKey

LEAD = timedelta(minutes=GUEST_EVENT_LEAD_MINUTES)
TRAIL = timedelta(minutes=GUEST_EVENT_TRAIL_MINUTES)
IP_SKEW = timedelta(minutes=GUEST_EVENT_IP_SKEW_MINUTES)
OPEN_STATUSES: tuple[str, ...] = (
    GuestSessionStatus.ACTIVE.value,
    GuestSessionStatus.PAUSED.value,
)


class Coverage(StrEnum):
    NOT_SENDING = "not_sending"
    NOT_SENDING_DURING_SESSION = "not_sending_during_session"
    COVERED = "covered"


class _SessionLike(Protocol):
    organization_id: Any
    location_id: Any
    router_id: Any
    device_id: Any
    ip_address: str | None
    status: str
    started_at: datetime
    ended_at: datetime | None
    last_activity_at: datetime


def session_end(session: _SessionLike, now: datetime) -> datetime:
    if session.ended_at is not None:
        return session.ended_at
    if session.status in OPEN_STATUSES:
        return now
    return session.last_activity_at


def session_window(session: _SessionLike, now: datetime) -> tuple[datetime, datetime]:
    """The (wider, DHCP) window an event may fall in to match the session."""
    return session.started_at - LEAD, session_end(session, now) + TRAIL


class GuestDeviceEventsReader:
    def __init__(self, repository: DeviceLogsRepository) -> None:
        self.repository = repository

    async def for_session(self, session: _SessionLike, *, now: datetime) -> dict:
        window_start, window_end = session_window(session, now)
        mac = await self.repository.device_mac(session.device_id)
        ip = (session.ip_address or "").strip() or None
        first_line = await self.repository.first_guest_line_at(
            organization_id=session.organization_id,
            location_id=session.location_id,
        )
        if first_line is None:
            coverage = Coverage.NOT_SENDING
        elif first_line > window_end:
            coverage = Coverage.NOT_SENDING_DURING_SESSION
        else:
            coverage = Coverage.COVERED

        events: list[dict[str, Any]] = []
        held_back = 0
        if coverage is Coverage.COVERED:
            key = SessionMatchKey(
                organization_id=session.organization_id,
                location_id=session.location_id,
                router_id=session.router_id,
                window_start=window_start,
                window_end=window_end,
                ip_window_start=session.started_at - IP_SKEW,
                ip_window_end=session_end(session, now) + IP_SKEW,
                mac_address=mac,
                ip_address=ip,
            )
            candidates = await self.repository.candidate_guest_events(
                key, limit=MAX_SESSION_DEVICE_EVENTS
            )
            matches = await self.repository.sessions_matching_events(
                [c.id for c in candidates],
                now=now,
                lead=LEAD,
                trail=TRAIL,
                ip_skew=IP_SKEW,
                open_statuses=OPEN_STATUSES,
            )
            for candidate in candidates:
                if matches.get(candidate.id) != 1:
                    held_back += 1
                    continue
                events.append(
                    {
                        "occurred_at": candidate.occurred_at,
                        "device_time": candidate.device_time,
                        "kind": candidate.kind,
                        "ip_address": candidate.ip_address,
                        "mac_address": candidate.mac_address,
                        "detail": candidate.detail,
                    }
                )
        return {
            "coverage": coverage.value,
            "logging_since": first_line,
            "linkable": bool(mac or ip),
            "window_start": window_start,
            "window_end": window_end,
            "events": events,
            "ambiguous_count": held_back,
        }

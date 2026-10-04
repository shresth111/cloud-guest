"""Aruba Instant On "access point silent" (P2-P): the pure half.

Verdicts and copy for ``constants.ALERT_TARGET_ACCESS_POINT_SILENT`` -- no
I/O, so every rule about *when* this alert fires is testable without a
database. ``service.AlertService._evaluate_access_point_silent_rule`` does the
reads and the alert bookkeeping; read ``ALERT_TARGET_ACCESS_POINT_SILENT``'s
comment in ``constants`` first for the design.

## What the copy may say

All this platform observes is that RADIUS traffic from a venue (or one of its
APs) stopped. From the cloud that is the same observation whether the AP lost
power, the venue's internet dropped, the Instant On RADIUS profile was
changed, or nobody is there. So no sentence here says "offline", "down" or
"ISP"; each one says what was seen, why it is unexpected, and where to look
(the Instant On app -- the only place the owner can see the AP itself).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.domains.captive_portal.validators import is_open_now

from .constants import (
    ACCESS_POINT_SILENT_DEFAULT_AP_SILENCE_MINUTES,
    ACCESS_POINT_SILENT_DEFAULT_OPEN_HOURS_SILENCE_MINUTES,
    ACCESS_POINT_SILENT_DEFAULT_SILENCE_MINUTES,
    ACCESS_POINT_SILENT_GUEST_SLACK_MINUTES,
)

_WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

#: Why a venue-level alert fired. Stored only in the copy, never a column.
REASON_GUESTS_CONNECTED = "guests_connected"
REASON_OPEN_HOURS = "open_hours"


@dataclass(frozen=True, slots=True)
class AccessPointSilentConfig:
    """``condition_config`` with every default applied. See
    ``validators.validate_access_point_silent_config`` for the shape."""

    silence: timedelta
    use_open_hours: bool
    open_hours_silence: timedelta
    per_access_point: bool
    access_point_silence: timedelta

    @classmethod
    def from_condition_config(
        cls, condition_config: dict[str, Any]
    ) -> AccessPointSilentConfig:
        def minutes(key: str, default: int) -> timedelta:
            value = condition_config.get(key)
            return timedelta(minutes=value if isinstance(value, int) else default)

        return cls(
            silence=minutes(
                "silence_minutes", ACCESS_POINT_SILENT_DEFAULT_SILENCE_MINUTES
            ),
            use_open_hours=condition_config.get("use_open_hours") is True,
            open_hours_silence=minutes(
                "open_hours_silence_minutes",
                ACCESS_POINT_SILENT_DEFAULT_OPEN_HOURS_SILENCE_MINUTES,
            ),
            per_access_point=condition_config.get("per_access_point") is True,
            access_point_silence=minutes(
                "access_point_silence_minutes",
                ACCESS_POINT_SILENT_DEFAULT_AP_SILENCE_MINUTES,
            ),
        )


def opened_at(
    *,
    enabled: bool,
    timezone: str,
    schedule: dict,
    now: datetime,
) -> datetime | None:
    """When today's Open Hours window started, if the venue is open *now* by
    its own schedule -- else ``None``. Open Hours switched off is ``None``
    too: "always open" is not evidence that guests are expected.

    "Open now" is ``captive_portal.validators.is_open_now`` -- the exact
    predicate the portal's sign-in gate uses -- so this alert can never call
    a venue open that the portal is showing as closed.
    """
    if not enabled:
        return None
    if not is_open_now(enabled=True, timezone=timezone, schedule=schedule, now=now):
        return None
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        zone = ZoneInfo("UTC")
    local = now.astimezone(zone)
    entry = schedule.get(_WEEKDAYS[local.weekday()]) or {}
    try:
        start = time.fromisoformat(entry.get("start"))
    except (TypeError, ValueError):
        return None
    return local.replace(hour=start.hour, minute=start.minute, second=0, microsecond=0)


def venue_silence_reason(
    *,
    now: datetime,
    last_radius_at: datetime | None,
    unclosed_guest_last_activity_at: datetime | None,
    open_since: datetime | None,
    config: AccessPointSilentConfig,
) -> str | None:
    """Should a venue-level alert OPEN? The reason, or ``None``.

    Never for a venue never heard from (``last_radius_at is None``): that is
    a venue not set up yet, an unanswered question rather than a finding.

    * ``REASON_GUESTS_CONNECTED`` -- silent past ``silence`` AND at least one
      guest the AP never signed off was still being reported when the venue
      went quiet (their last report within
      ``ACCESS_POINT_SILENT_GUEST_SLACK_MINUTES`` of the last packet).
    * ``REASON_OPEN_HOURS`` -- only with ``use_open_hours``: the venue is
      open by its own schedule, and has been both open and silent for
      ``open_hours_silence``. Silence is counted from whichever is later,
      the last packet or today's opening -- so a venue is never paged at
      opening time for last night's quiet.
    """
    if last_radius_at is None:
        return None
    if now - last_radius_at < config.silence:
        return None
    if unclosed_guest_last_activity_at is not None and (
        unclosed_guest_last_activity_at
        >= last_radius_at - timedelta(minutes=ACCESS_POINT_SILENT_GUEST_SLACK_MINUTES)
    ):
        return REASON_GUESTS_CONNECTED
    if (
        config.use_open_hours
        and open_since is not None
        and now - max(last_radius_at, open_since) >= config.open_hours_silence
    ):
        return REASON_OPEN_HOURS
    return None


def venue_heard_again(
    *, now: datetime, last_radius_at: datetime | None, config: AccessPointSilentConfig
) -> bool:
    """Should an OPEN venue-level alert resolve? Only on positive evidence:
    a packet inside the silence window. Guests aging out of the evidence, or
    the venue closing for the night, holds the alert open."""
    return last_radius_at is not None and now - last_radius_at < config.silence


def access_point_is_silent(
    *,
    now: datetime,
    last_seen_at: datetime | None,
    sibling_last_seen: list[datetime | None],
    config: AccessPointSilentConfig,
    seen_lookback: timedelta,
) -> bool:
    """Should a per-AP alert OPEN? An approved AP that served guests
    recently (seen within ``seen_lookback``) and has been quiet past
    ``access_point_silence`` while at least one sibling AP at the same venue
    was heard within ``silence``. The sibling is the evidence that guests
    are on site; without one, a quiet AP is just a quiet venue (which the
    venue-level half judges)."""
    if last_seen_at is None:
        return False
    quiet_for = now - last_seen_at
    if quiet_for < config.access_point_silence or quiet_for > seen_lookback:
        return False
    return any(
        seen is not None and now - seen < config.silence for seen in sibling_last_seen
    )


def access_point_heard_again(
    *, now: datetime, last_seen_at: datetime | None, config: AccessPointSilentConfig
) -> bool:
    """Should an OPEN per-AP alert resolve? Positive evidence only."""
    return last_seen_at is not None and now - last_seen_at < config.access_point_silence


# ----------------------------------------------------------------------------
# Copy
# ----------------------------------------------------------------------------


def format_quiet_for(delta: timedelta) -> str:
    """``"45 minutes"``, ``"2 hours"``, ``"2 hours 10 minutes"``."""
    total = max(int(delta.total_seconds() // 60), 1)
    hours, minutes = divmod(total, 60)
    parts: list[str] = []
    if hours:
        parts.append(f"{hours} hour" + ("s" if hours != 1 else ""))
    if minutes or not hours:
        parts.append(f"{minutes} minute" + ("s" if minutes != 1 else ""))
    return " ".join(parts)


def venue_silent_message(
    venue_name: str, *, reason: str, quiet_for: timedelta, guests: int
) -> str:
    if reason == REASON_GUESTS_CONNECTED:
        who = "1 guest was" if guests == 1 else f"{guests} guests were"
        return (
            f"{venue_name}: no guest sign-ins or usage reports from your Aruba "
            f"Instant On access points for {format_quiet_for(quiet_for)}, "
            f"although {who} still connected when they went quiet. Guests may "
            "be unable to get online. We can't tell from here whether the "
            "access points lost power or internet, or stopped sending to Wyfy "
            "-- please check them in the Instant On app."
        )
    return (
        f"{venue_name}: no guest activity from your Aruba Instant On access "
        f"points for {format_quiet_for(quiet_for)} during your open hours. "
        "This can simply mean no guests have connected; if guests are on "
        "site, please check the access points in the Instant On app."
    )


def venue_heard_message(venue_name: str) -> str:
    return (
        f"{venue_name}: your Aruba Instant On access points are reporting "
        "guest activity again."
    )


VENUE_GONE_MESSAGE = (
    "This venue is no longer an Aruba Instant On venue on your account, so "
    "this alert was closed."
)


def access_point_label(name: str | None, mac: str) -> str:
    return f"{name} ({mac})" if name else mac


def access_point_silent_message(
    venue_name: str, ap_label: str, *, quiet_for: timedelta
) -> str:
    return (
        f"Access point {ap_label} at {venue_name}: no guest activity for "
        f"{format_quiet_for(quiet_for)}, while other access points there are "
        "serving guests. It may be switched off, disconnected, or out of "
        "reach of guests -- please check it in the Instant On app."
    )


def access_point_heard_message(venue_name: str, ap_label: str) -> str:
    return (
        f"Access point {ap_label} at {venue_name} is reporting guest " "activity again."
    )


def access_point_gone_message(ap_label: str | None) -> str:
    subject = f"Access point {ap_label}" if ap_label else "This access point"
    return (
        f"{subject} was removed or is no longer approved for this venue, so "
        "this alert was closed."
    )


__all__ = [
    "REASON_GUESTS_CONNECTED",
    "REASON_OPEN_HOURS",
    "VENUE_GONE_MESSAGE",
    "AccessPointSilentConfig",
    "access_point_gone_message",
    "access_point_heard_again",
    "access_point_heard_message",
    "access_point_is_silent",
    "access_point_label",
    "access_point_silent_message",
    "format_quiet_for",
    "opened_at",
    "venue_heard_again",
    "venue_heard_message",
    "venue_silence_reason",
    "venue_silent_message",
]

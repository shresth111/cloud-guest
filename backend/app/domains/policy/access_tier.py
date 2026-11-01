"""Access Tiers: what a tier carries, and how it lands on a guest.

An **Access Tier** (customer dashboard -> Access & Policy -> Access Tiers,
``CreateGroup.tsx``) is a ``PolicyType.BANDWIDTH`` policy. A guest is *in* a
tier when an active ``PolicyAssignment`` targets them by id
(``target_type="guest"``) at the location they sign in at -- the "Map guests"
step. Mapping the tier to a location without naming a guest
(``target_type="none"``) is the venue-wide speed and stays exactly that.

## The bug this module exists for

A tier's form carries more than a speed: session timeout, idle timeout,
devices per user, a daily (max session per day) limit, login hours and a
data limit. All of them were saved into the tier's BANDWIDTH ``rules`` and
**nothing ever read them**: every reader resolves ``SESSION``/``DEVICE``/
``FUP`` and a BANDWIDTH policy is never a candidate for those types. The
data limit, the daily limit and login hours did nothing at all, on every
vendor (found 2026-10-03).

## The fix: the tier is the source of truth, overlaid at resolution

``PolicyService.resolve_effective_policy`` overlays the guest's tier onto
every ``SESSION``/``DEVICE``/``FUP`` resolution that names a ``guest_id``
(``tier_overrides`` below), so every existing reader -- the five sign-in
methods, the RADIUS authorize path, the mid-session byte check, the FUP
time-accrual sweep -- picks the tier up from the one place they all already
call, with no reader-side change and no backfill for tiers saved before
this existed. Login hours have no policy type to land on; readers ask for
the tier itself (``PolicyService.resolve_access_tier``) and evaluate
``login_hours_standing``.

## Precedence (one rule per field)

1. A tier field that is **set** overrides the venue's own value
   (location / organization / platform default) for a guest in that tier.
2. A tier field that is ``None`` (or absent) is **not set**: the venue's
   own value applies unchanged.
3. "No limit" is an explicit value, not ``None``, so a tier can lift a
   venue cap: ``daily_limit_minutes = 0`` and ``data_limit.quota = 0``
   mean "no limit for this tier" and *clear* the venue's cap;
   ``devices_per_user`` uses the same 9999 ceiling the DEVICE policy does.
4. A tier's ``data_limit`` replaces the venue's data caps as a whole (all
   three periods): a tier that says "5 GB a week" must not be cut short by
   the venue's 1 GB a day. ``daily_limit_minutes`` replaces only the daily
   time cap, the one the venue screen also sets.
5. Login hours narrow, never widen: the venue's own Open Hours still apply.

The overlay *replaces values*; it never adds a second cap. Usage counters are
per guest and period, not per policy, so nothing is counted twice even when a
paired SESSION/DEVICE policy written by the dashboard holds the same value.

Pure functions only -- ``policy`` stays a leaf (see ``constants.py``).
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import PolicyType

#: Policy types a tier is overlaid onto. BANDWIDTH is not here: the tier IS
#: the BANDWIDTH policy, and a guest-targeted assignment already wins that
#: resolution on its own (``_TARGET_SPECIFICITY``).
TIER_OVERLAY_POLICY_TYPES: frozenset[PolicyType] = frozenset(
    {PolicyType.SESSION, PolicyType.DEVICE, PolicyType.FUP}
)

#: ``data_limit.resets`` -> the FUP key it lands on. ``"session"`` has no FUP
#: key: it is stamped onto the session row (``GuestSession.data_limit_mb``,
#: the per-session allowance a voucher batch already uses).
DATA_LIMIT_PERIOD_KEYS: dict[str, str] = {
    "daily": "daily_data_limit_mb",
    "weekly": "weekly_data_limit_mb",
    "monthly": "monthly_data_limit_mb",
}
FUP_DATA_LIMIT_KEYS: tuple[str, ...] = tuple(DATA_LIMIT_PERIOD_KEYS.values())

_UNIT_TO_MB: dict[str, float] = {"mb": 1, "gb": 1024, "tb": 1024 * 1024}

_DAY_INDEX: dict[str, int] = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}


def _positive_int_or_none(value: object, *, allow_zero: bool = False) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = int(value)
    if number < 0 or (number == 0 and not allow_zero):
        return None
    return number


def normalize_reset_period(value: object) -> str | None:
    """``"Per session"``/``"Daily"``/``"Weekly"``/``"Monthly"`` (the
    dashboard's labels, any case or separator) -> ``session``/``daily``/
    ``weekly``/``monthly``. Anything else -> ``None`` (the data limit is then
    ignored rather than guessed at)."""
    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace("_", " ").replace("-", " ")
    if key in {"per session", "session", "each session"}:
        return "session"
    if key in {"daily", "day", "per day"}:
        return "daily"
    if key in {"weekly", "week", "per week"}:
        return "weekly"
    if key in {"monthly", "month", "per month"}:
        return "monthly"
    return None


def data_limit_to_mb(data_limit: object) -> int | None:
    """A tier's ``data_limit`` ``{quota, unit}`` as whole megabytes (rounded
    up, so a cap is never looser than configured). ``0`` means "no data
    limit"; ``None`` means the field is unusable / not set."""
    if not isinstance(data_limit, dict):
        return None
    quota = data_limit.get("quota")
    if isinstance(quota, bool) or not isinstance(quota, int | float) or quota < 0:
        return None
    unit = str(data_limit.get("unit") or "MB").strip().lower()
    factor = _UNIT_TO_MB.get(unit)
    if factor is None:
        return None
    return math.ceil(quota * factor)


@dataclass(frozen=True, slots=True)
class AccessTier:
    """The guest-relevant half of a tier's BANDWIDTH ``rules``. Every field
    ``None`` = not set by the tier (see module docstring, "Precedence")."""

    policy_id: uuid.UUID
    name: str | None
    download_rate_kbps: int | None
    upload_rate_kbps: int | None
    session_timeout_minutes: int | None
    idle_timeout_minutes: int | None
    devices_per_user: int | None
    daily_limit_minutes: int | None
    #: ``None`` = not set; ``0`` = no data limit for this tier.
    data_limit_mb: int | None
    #: ``session``/``daily``/``weekly``/``monthly``, or ``None`` when no
    #: usable data limit is set.
    data_limit_period: str | None
    login_hours: dict[str, Any] | None

    @property
    def session_data_limit_mb(self) -> int | None:
        """The per-session data cap to stamp on a new session, or ``None``.
        ``0`` ("no limit") is never stamped -- a session row's ``0`` would be
        a zero-byte allowance, not an unlimited one."""
        if self.data_limit_period == "session" and self.data_limit_mb:
            return self.data_limit_mb
        return None


def access_tier_from_rules(
    policy_id: uuid.UUID, rules: dict[str, Any] | None, *, name: str | None = None
) -> AccessTier:
    """Tolerant read of a tier's stored rules: a malformed field reads as
    "not set" rather than raising, because this runs on the sign-in path and
    a bad row must degrade to the venue's own limits, never to "no WiFi"."""
    rules = rules or {}
    data_limit = rules.get("data_limit")
    period = normalize_reset_period(
        data_limit.get("resets") if isinstance(data_limit, dict) else None
    )
    limit_mb = data_limit_to_mb(data_limit) if period is not None else None
    login_hours = rules.get("login_hours")
    return AccessTier(
        policy_id=policy_id,
        name=name,
        download_rate_kbps=_positive_int_or_none(
            rules.get("download_rate_kbps"), allow_zero=True
        ),
        upload_rate_kbps=_positive_int_or_none(
            rules.get("upload_rate_kbps"), allow_zero=True
        ),
        session_timeout_minutes=_positive_int_or_none(
            rules.get("session_timeout_minutes")
        ),
        idle_timeout_minutes=_positive_int_or_none(rules.get("idle_timeout_minutes")),
        devices_per_user=_positive_int_or_none(rules.get("devices_per_user")),
        daily_limit_minutes=_positive_int_or_none(
            rules.get("daily_limit_minutes"), allow_zero=True
        ),
        data_limit_mb=limit_mb,
        data_limit_period=period if limit_mb is not None else None,
        login_hours=login_hours if isinstance(login_hours, dict) else None,
    )


def tier_overrides(policy_type: PolicyType, tier: AccessTier) -> dict[str, Any]:
    """The ``rules`` keys ``tier`` sets for ``policy_type``. Applied with
    ``dict.update`` on top of the venue's resolved rules -- see the module
    docstring for the precedence each mapping follows."""
    overrides: dict[str, Any] = {}
    if policy_type == PolicyType.SESSION:
        if tier.session_timeout_minutes is not None:
            overrides["session_timeout_minutes"] = tier.session_timeout_minutes
        if tier.idle_timeout_minutes is not None:
            overrides["idle_timeout_minutes"] = tier.idle_timeout_minutes
    elif policy_type == PolicyType.DEVICE:
        if tier.devices_per_user is not None:
            overrides["max_devices_per_guest"] = tier.devices_per_user
    elif policy_type == PolicyType.FUP:
        if tier.daily_limit_minutes is not None:
            # 0 = "No limit": clear the venue's daily cap. FUP reads 0 as a
            # real zero-minute cap, so it must become None, never 0.
            overrides["daily_time_limit_minutes"] = tier.daily_limit_minutes or None
        if tier.data_limit_period is not None:
            for key in FUP_DATA_LIMIT_KEYS:
                overrides[key] = None
            period_key = DATA_LIMIT_PERIOD_KEYS.get(tier.data_limit_period)
            if period_key is not None and tier.data_limit_mb:
                overrides[period_key] = tier.data_limit_mb
    return overrides


# ============================================================================
# Login hours
# ============================================================================


def _parse_hhmm(value: object) -> time | None:
    if not isinstance(value, str):
        return None
    try:
        return time.fromisoformat(value.strip())
    except ValueError:
        return None


def _day_indexes(days: object) -> set[int] | None:
    """``["Mon", "tuesday", ...]`` -> weekday indexes. ``[]``/missing = every
    day. ``None`` when nothing in the list is a weekday (malformed)."""
    if not days:
        return set(range(7))
    if not isinstance(days, list):
        return None
    out = {
        _DAY_INDEX[d.strip().lower()[:3]]
        for d in days
        if isinstance(d, str) and d.strip().lower()[:3] in _DAY_INDEX
    }
    return out or None


def _zone(tz_name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(tz_name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def login_hours_standing(
    login_hours: dict[str, Any] | None,
    *,
    tz_name: str | None,
    now: datetime | None = None,
) -> int | str | None:
    """Where ``now`` falls against a tier's login-hours window.

    * ``None``     -- no usable window (not set, or malformed): no restriction.
      Malformed reads as open on purpose: this runs on the sign-in path.
    * ``"closed"`` -- outside the window: refuse the sign-in / end the session.
    * ``int``      -- inside it: seconds until the window closes (>= 1), for
      capping ``Session-Timeout``.

    ``days`` names the day a window *starts*; ``start > end`` is an
    overnight window (22:00-06:00 on Fri runs into Saturday morning);
    ``start == end`` is all day. ``end`` is inclusive to the end of that
    minute, matching Open Hours' ``seconds_until_closing``."""
    if not isinstance(login_hours, dict):
        return None
    start = _parse_hhmm(login_hours.get("start_time"))
    end = _parse_hhmm(login_hours.get("end_time"))
    days = _day_indexes(login_hours.get("days"))
    if start is None or end is None or days is None:
        return None
    zone = _zone(tz_name)
    moment = (now or datetime.now(UTC)).astimezone(zone)

    def _window(day_start: datetime) -> tuple[datetime, datetime]:
        opens = day_start.replace(
            hour=start.hour, minute=start.minute, second=0, microsecond=0
        )
        closes = day_start.replace(
            hour=end.hour, minute=end.minute, second=59, microsecond=999999
        )
        if start == end:
            closes = opens + timedelta(days=1) - timedelta(microseconds=1)
        elif start > end:
            closes = closes + timedelta(days=1)
        return opens, closes

    # A window can only contain ``moment`` if it started today or (overnight
    # / all-day) yesterday.
    for back in (0, 1):
        day = moment - timedelta(days=back)
        if day.weekday() not in days:
            continue
        opens, closes = _window(day)
        if opens <= moment <= closes:
            return max(math.ceil((closes - moment).total_seconds()), 1)
    return "closed"


__all__ = [
    "AccessTier",
    "DATA_LIMIT_PERIOD_KEYS",
    "FUP_DATA_LIMIT_KEYS",
    "TIER_OVERLAY_POLICY_TYPES",
    "access_tier_from_rules",
    "data_limit_to_mb",
    "login_hours_standing",
    "normalize_reset_period",
    "tier_overrides",
]

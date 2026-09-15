"""Pure, side-effect-free validation for the Guest domain.

Mirrors ``app.domains.voucher.validators``/``app.domains.captive_portal
.validators``'s identical discipline: no I/O, just "is this a legal input
or transition" checks the service layer calls before touching the database.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import (
    BYTES_PER_MB,
    DASHBOARD_SERIES_BUCKET_SECONDS,
    GUEST_SESSION_STATUS_TRANSITIONS,
    MAX_DASHBOARD_SERIES_WINDOW_DAYS,
    NAS_STATUS_TRANSITIONS,
    DashboardSeriesBucket,
    GuestSessionStatus,
    NasStatus,
    QuotaPeriodType,
)
from .exceptions import (
    InvalidAnalyticsDateRangeError,
    InvalidDashboardSeriesRangeError,
    InvalidExtensionMinutesError,
    InvalidNasStatusTransitionError,
    InvalidSessionStatusTransitionError,
)
from .models import Guest, GuestSession


def guest_has_profile(guest: Guest) -> bool:
    """Whether the post-connect "add your name / add your email" card has
    already been answered by this guest -- either by giving something, or
    by explicitly declining.

    This is the value behind ``schemas.GuestLoginResponse.has_profile``,
    and it exists as one function rather than an inline expression in
    ``router._login_response`` because two surfaces read it (``POST
    /guest/login/*`` and ``GET /guest/session/active``) and a third-hand
    copy of "or the guest declined" is exactly the kind of clause that
    gets dropped.

    **Why this and not ``is_new_guest``.** The shipped card gates on
    ``is_new_guest``, and that is the wrong key -- a venue that switches
    the ask on in October has, on day one, a guest base of thousands who
    are all ``is_new_guest == False`` and all have no name on file, and
    not one of them will ever be asked. Under ``has_profile`` they are
    asked once, then never again. It is the same key the neighbouring
    ``has_password``/``has_pin`` bits already use for the same purpose,
    and it costs the same to compute.

    Ask *once ever*, not *on first login*.
    """
    return bool(
        guest.display_name or guest.email or guest.profile_prompt_declined_at
    )


def guest_has_opened_review_link(guest: Guest) -> bool:
    """Whether this guest has already tapped through to the venue's Google
    review link -- the value behind
    ``schemas.GuestLoginResponse.has_opened_review_link``.

    One function rather than an inline ``bool(...)`` for the same reason
    ``guest_has_profile`` is one: the login response and
    ``GET /guest/session/active`` both derive it, and the portal treats a
    tap as final. A second copy of that rule is how one surface comes to
    keep asking a guest who already went.

    It answers "was the link opened", never "was a review written".
    Google exposes nothing that would tell this platform the difference.
    """
    return guest.review_link_opened_at is not None


def normalize_mac_address(mac_address: str) -> str:
    """Uppercases and strips a MAC address -- mirrors
    ``app.domains.router.service._normalize_mac``'s identical convention,
    so the same physical device is always recognized regardless of the
    case/whitespace a captive-portal frontend happens to submit it in."""
    return mac_address.strip().upper()


def normalize_identifier(identifier: str) -> str:
    """Strips surrounding whitespace -- mirrors
    ``app.domains.voucher.validators.normalize_redeemed_identifier``'s
    identical, deliberately unopinionated normalization (this module has no
    delivery channel of its own to protect; channel-specific shape
    validation already happened inside ``app.domains.otp`` before this
    module ever sees the identifier)."""
    return identifier.strip()


def validate_session_status_transition(
    *, current: GuestSessionStatus, target: GuestSessionStatus
) -> None:
    """Consults the exhaustive ``GUEST_SESSION_STATUS_TRANSITIONS`` graph.

    Deliberately has no "same status is a no-op" shortcut -- e.g.
    disconnecting an already-``DISCONNECTED`` session must raise (every
    non-``ACTIVE`` status has no outgoing edges at all, including to
    itself), mirroring ``app.domains.router.service.RouterService
    ._validate_transition``'s identical discipline."""
    legal_targets = GUEST_SESSION_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidSessionStatusTransitionError(current.value, target.value)


def validate_nas_status_transition(*, current: NasStatus, target: NasStatus) -> None:
    """Consults the exhaustive ``NAS_STATUS_TRANSITIONS`` graph. Deliberately
    has no "same status is a no-op" shortcut -- e.g. disabling an
    already-``DISABLED`` NAS must raise (``DELETED`` has no outgoing edges
    at all, including to itself), mirroring
    ``validate_session_status_transition``'s identical discipline."""
    legal_targets = NAS_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidNasStatusTransitionError(current.value, target.value)


def is_session_timed_out(session: GuestSession, *, now: datetime) -> bool:
    """Whether ``session`` has been inactive longer than its own
    ``session_timeout_minutes`` -- a pure, in-memory check used both by
    ``GuestService.enforce_timeouts`` (after the repository's own SQL-level
    filter already narrowed candidates) and directly by tests. Returns
    ``False`` when no timeout was ever recorded for this session (an
    unbounded session)."""
    if session.session_timeout_minutes is None:
        return False
    elapsed_minutes = (now - session.last_activity_at).total_seconds() / 60
    return elapsed_minutes >= session.session_timeout_minutes


def has_session_reached_time_limit(session: GuestSession, *, now: datetime) -> bool:
    """Whether ``session`` has been open, in wall-clock terms, for at
    least its own ``session_timeout_minutes`` -- measured from
    ``started_at``, deliberately **not** from ``last_activity_at``.

    This is the same number ``is_session_timed_out`` above reads, and the
    two mean genuinely different things by it. That is not an accident to
    be tidied away; it is a real split that this predicate exists to name:

    * ``is_session_timed_out`` measures **idleness** and drives the
      Celery sweep. Every RADIUS Interim-Update refreshes
      ``last_activity_at`` (``GuestService.record_usage``), and the
      Authorize reply asks for one every 300s, so a guest who is actually
      using the WiFi has that timestamp refreshed indefinitely and the
      sweep can never expire them. It only ever catches abandoned
      sessions -- which is a useful thing to catch, and is all it should
      be relied on for.
    * ``Session-Timeout``, the RADIUS reply attribute built from the very
      same column (``RadiusService.authorize``), is absolute elapsed time
      from the NAS's own session start. RouterOS drops the guest at 30
      minutes of *being connected*, whatever they were doing.

    So a venue that picks "30 min" in Guest WiFi Limits gets two
    mechanisms that disagree: the router cuts a busy guest off at 30
    minutes and the platform's own records say the session is still
    ACTIVE. This predicate takes the **router's** meaning, because that is
    the one a guest actually experiences and the one the operator meant:
    the dropdown says "Re-authenticate after this much time", not "after
    this much silence".

    It is used at the three places where the platform's answer must match
    what the network already did -- the two guest-facing session reads and
    the Authorize reply -- so that a guest whose router-side session has
    run out is never told they are still connected, and is never handed a
    fresh full timeout for a session that has already spent it.

    ``False`` when no timeout was recorded (an unbounded session), exactly
    like ``is_session_timed_out``.
    """
    if session.session_timeout_minutes is None:
        return False
    elapsed_minutes = (now - session.started_at).total_seconds() / 60
    return elapsed_minutes >= session.session_timeout_minutes


_ROUTEROS_DURATION_TOKEN = re.compile(r"(\d+)(w|d|h|ms|us|s|m)")
_ROUTEROS_DURATION_UNIT_SECONDS: dict[str, float] = {
    "w": 7 * 86400,
    "d": 86400,
    "h": 3600,
    "m": 60,
    "s": 1,
    "ms": 0.001,
    "us": 0.000001,
}
_ROUTEROS_CLOCK_DURATION = re.compile(r"^(?:(\d+)d)?(\d+):(\d{2}):(\d{2})$")


def parse_routeros_duration_seconds(value: object) -> float | None:
    """A RouterOS API duration (``"1w2d3h4m5s"``, ``"5m32s"``, ``"250ms"``,
    or the older ``"00:05:32"`` clock form) in seconds -- ``None`` for an
    absent, empty or unparseable value, so a caller can tell "RouterOS did
    not say" apart from "RouterOS said zero".

    Its own parser rather than ``isp.device_adapters``'s: that one has no
    ``w`` unit, and a hotspot host that has been silent for over a week is
    exactly the row this is used to catch."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    clock = _ROUTEROS_CLOCK_DURATION.match(text)
    if clock is not None:
        days, hours, minutes, seconds = clock.groups()
        return (
            int(days or 0) * 86400
            + int(hours) * 3600
            + int(minutes) * 60
            + int(seconds)
        )
    tokens = _ROUTEROS_DURATION_TOKEN.findall(text)
    if not tokens or "".join(a + u for a, u in tokens) != text:
        return None
    return sum(
        int(amount) * _ROUTEROS_DURATION_UNIT_SECONDS[unit] for amount, unit in tokens
    )


def _routeros_flag(value: object) -> bool:
    """librouteros hands ``true``/``false`` back as real booleans, but a
    reply that went through any other path may carry the strings."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes"}


def hotspot_is_serving(server_rows: Sequence[Mapping[str, object]]) -> bool:
    """Whether at least one ``/ip/hotspot`` server on the router is enabled.

    The presence sweep's precondition, and the reason it is one: an empty
    ``/ip/hotspot/host`` table means "nobody is here" only on a router that
    is actually running a hotspot. On a router whose hotspot is disabled or
    was never configured it means nothing at all, and reading it as
    "everyone has left" would close every session on that router."""
    return any(not _routeros_flag(row.get("disabled", False)) for row in server_rows)


def present_macs_from_hotspot_hosts(
    host_rows: Sequence[Mapping[str, object]], *, dead_after_seconds: float
) -> frozenset[str]:
    """The normalized MACs RouterOS currently considers on the network,
    from its ``/ip/hotspot/host`` table.

    That table is the one list on the device that holds *every* host behind
    the hotspot, whichever way it got through: an authenticated login
    (``authorized=true``), an ``ip-binding type=bypassed`` row
    (``bypassed=true`` -- how this fleet actually admits guests), or a
    device still sitting on the portal. ``/ip/hotspot/active`` holds only
    the first, so it would report every bypassed guest as gone.

    A row whose ``host-dead-time`` has reached ``dead_after_seconds`` is
    left out -- see ``constants.SESSION_PRESENCE_HOST_DEAD_AFTER_SECONDS``.
    A row with no parseable ``host-dead-time`` counts as present: when in
    doubt, the guest is still here."""
    present: set[str] = set()
    for row in host_rows:
        mac = row.get("mac-address")
        if not mac:
            continue
        dead_for = parse_routeros_duration_seconds(row.get("host-dead-time"))
        if dead_for is not None and dead_for >= dead_after_seconds:
            continue
        present.add(normalize_mac_address(str(mac)))
    return frozenset(present)


def is_session_presence_judgeable(
    session: GuestSession, *, now: datetime, grace_minutes: int
) -> bool:
    """Whether ``session`` is old enough for the presence sweep to close it
    on the router's say-so -- both its ``started_at`` and its
    ``last_activity_at`` must be at least ``grace_minutes`` in the past. See
    ``constants.SESSION_PRESENCE_GRACE_MINUTES``."""
    cutoff = now - timedelta(minutes=grace_minutes)
    return session.started_at <= cutoff and session.last_activity_at <= cutoff


def is_quota_exceeded(session: GuestSession) -> bool:
    """Whether ``session``'s cumulative ``bytes_uploaded +
    bytes_downloaded`` has reached or exceeded its own ``data_limit_mb`` --
    a pure check, see ``service.py``'s module docstring for why this (like
    timeout detection) is a reporting/status-transition signal, not a live
    network-level enforcement mechanism in this sandbox. Returns ``False``
    when no limit was ever recorded for this session (unlimited data)."""
    if session.data_limit_mb is None:
        return False
    return session.total_bytes() >= session.data_limit_mb * BYTES_PER_MB


def validate_date_range(start: datetime, end: datetime) -> None:
    """Raises ``InvalidAnalyticsDateRangeError`` if ``start`` is after
    ``end`` -- guards every ``GuestAnalyticsService`` query before it ever
    reaches a SQL aggregate."""
    if start > end:
        raise InvalidAnalyticsDateRangeError()


def as_utc(value: datetime) -> datetime:
    """A timezone-naive query datetime is taken to be UTC; an aware one is
    converted to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def validate_dashboard_series_window(start: datetime, end: datetime) -> None:
    """The dashboard series window is half-open ``[start, end)``: it must be
    non-empty and at most ``MAX_DASHBOARD_SERIES_WINDOW_DAYS`` long."""
    if end <= start:
        raise InvalidDashboardSeriesRangeError("end_date must be after start_date")
    if end - start > timedelta(days=MAX_DASHBOARD_SERIES_WINDOW_DAYS):
        raise InvalidDashboardSeriesRangeError(
            f"date range must not exceed {MAX_DASHBOARD_SERIES_WINDOW_DAYS} days"
        )


def dashboard_series_bucket_starts(
    *,
    start: datetime,
    end: datetime,
    bucket: DashboardSeriesBucket,
    tz_offset_minutes: int,
) -> list[datetime]:
    """Every bucket start (UTC) covering ``[start, end)``, ascending.

    Buckets align to the caller's *local* hour/midnight for a fixed UTC offset
    (IST = 330): shift into local wall-clock, floor, shift back. If ``start``
    is not itself on a boundary, the first bucket starts before it -- that
    bucket's counts are still clipped to the window by the repository."""
    offset = timedelta(minutes=tz_offset_minutes)
    local_start = start + offset
    if bucket is DashboardSeriesBucket.HOUR:
        floored = local_start.replace(minute=0, second=0, microsecond=0)
    else:
        floored = local_start.replace(hour=0, minute=0, second=0, microsecond=0)
    step = timedelta(seconds=DASHBOARD_SERIES_BUCKET_SECONDS[bucket])
    current = floored - offset
    starts: list[datetime] = []
    while current < end:
        starts.append(current)
        current += step
    return starts


def classify_dashboard_os(user_agent: str | None) -> str:
    """Python statement of the OS precedence the repository's SQL ``CASE``
    implements (``GuestRepository.get_dashboard_series``); the two are held
    together by a parity test. Lowercase substring matching, first hit wins."""
    ua = (user_agent or "").lower()
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        return "iOS"
    if "android" in ua:
        return "Android"
    if "windows" in ua:
        return "Windows"
    if "mac os" in ua or "macintosh" in ua:
        return "macOS"
    if "linux" in ua:
        return "Linux"
    return "Other"


def is_concurrent_session_limit_reached(*, active_count: int, limit: int) -> bool:
    """Guest Session Engine (Phase 1): a pure, in-memory comparison used by
    ``GuestService._enforce_concurrent_session_limit`` after the
    repository's own ``count_active_sessions_for_guest`` has already fetched
    ``active_count`` -- mirrors ``is_session_timed_out``'s/
    ``is_quota_exceeded``'s identical "repository fetches, this module
    decides" split. A guest with exactly ``limit`` active sessions has
    *reached* the limit (the next login would exceed it), so this is
    ``>=``, not ``>``."""
    return active_count >= limit


def is_device_limit_reached(*, device_count: int, limit: int) -> bool:
    """Guest Session Engine (Phase 1): a pure, in-memory comparison used by
    ``GuestService._enforce_device_limit`` after the repository's own
    ``count_active_devices_for_guest`` has already fetched ``device_count``
    (distinct devices currently holding ``ACTIVE`` sessions -- the basis is
    connected, not registered) -- mirrors
    ``is_concurrent_session_limit_reached``'s identical shape and
    ``>=`` (not ``>``) reasoning: a guest with exactly ``limit`` devices
    connected at the same time has already reached it."""
    return device_count >= limit


def compute_period_start(
    period_type: QuotaPeriodType, *, now: datetime, tz_name: str
) -> datetime:
    """The current wall-clock boundary (returned as a UTC-aware
    ``datetime``) of ``period_type``'s recurring calendar period, as of
    ``now``, in the ``tz_name`` (an IANA zone name, e.g.
    ``Organization.timezone``) local calendar -- the single place
    ``GuestQuotaUsage``'s "has this row's period rolled over" comparison is
    computed, shared by every caller (the lazy, request-triggered rollover
    in ``service._get_or_reset_quota_usage`` and the proactive
    ``tasks.run_quota_reset_sweep``) so there is exactly one, non-divergent
    definition of "when does a guest's day/week/month roll over" in this
    codebase. ``WEEKLY`` starts on Monday (ISO weekday convention), mirroring
    ``schemas.TimeWindow.days_of_week``'s own ``0``=Monday convention.
    Falls back to UTC if ``tz_name`` is not a recognized IANA zone --
    mirrors ``Organization.timezone``'s own ``default="UTC"``, never
    raising over a malformed/stale stored zone name."""
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz = ZoneInfo("UTC")
    local_now = now.astimezone(tz)
    local_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period_type == QuotaPeriodType.DAILY:
        local_start = local_midnight
    elif period_type == QuotaPeriodType.WEEKLY:
        local_start = local_midnight - timedelta(days=local_midnight.weekday())
    else:
        local_start = local_midnight.replace(day=1)
    return local_start.astimezone(UTC)


def validate_extension_minutes(additional_minutes: int) -> None:
    """Guest Session Engine (Phase 1): raises
    ``InvalidExtensionMinutesError`` for a non-positive value -- called by
    ``GuestService.extend_session`` before touching the database."""
    if additional_minutes <= 0:
        raise InvalidExtensionMinutesError(additional_minutes)


def is_fup_usage_exceeded(*, used: int, limit: int) -> bool:
    """Guest Session Engine (Phase 1): a pure, in-memory comparison used by
    ``GuestService``'s FUP enforcement call sites once a
    ``GuestQuotaUsage`` row's ``bytes_used``/``minutes_used`` has already
    been fetched (or just bumped) -- mirrors
    ``is_device_limit_reached``'s/``is_concurrent_session_limit_reached``'s
    identical ``>=`` (not ``>``) reasoning: a guest with usage exactly
    equal to their configured limit has already reached it. Callers are
    responsible for skipping this entirely when no limit is configured for
    a given period (``None``, not ``0`` -- see ``schemas.FUPPolicyRules``'s
    own docstring); this function only ever compares two already-resolved
    integers."""
    return used >= limit


_SEQUENTIAL_ASCENDING_DIGITS = "0123456789"
_SEQUENTIAL_DESCENDING_DIGITS = "9876543210"


def is_weak_pin(pin: str) -> bool:
    """True for a Portal PIN that is trivially guessable: every digit
    identical (``"000000"``, ``"111111"``, ...) or a straight ascending/
    descending run (``"123456"``, ``"654321"``, ...) -- the two shapes any
    real-world "don't pick this PIN" guide lists first, and the two an
    attacker would try before anything else. A small, explicit structural
    check rather than a comprehensive weak-PIN policy engine, mirroring
    ``PasswordManager.validate_strength``'s own ``_COMMON_PASSWORDS``
    blocklist in spirit (a short, targeted rejection list) without
    reimplementing that module's letter/digit/special-character rules,
    which a fixed-length numeric PIN could never satisfy in the first
    place. Called by ``GuestService.set_guest_pin`` -- never assumes
    ``pin`` is a particular length; a run/all-same-digit check is
    meaningful at any length ``constants.PIN_LENGTH`` might ever be."""
    if len(set(pin)) == 1:
        return True
    return pin in _SEQUENTIAL_ASCENDING_DIGITS or pin in _SEQUENTIAL_DESCENDING_DIGITS


__all__ = [
    "guest_has_profile",
    "guest_has_opened_review_link",
    "normalize_mac_address",
    "normalize_identifier",
    "is_weak_pin",
    "validate_session_status_transition",
    "validate_nas_status_transition",
    "is_session_timed_out",
    "parse_routeros_duration_seconds",
    "hotspot_is_serving",
    "present_macs_from_hotspot_hosts",
    "is_session_presence_judgeable",
    "is_quota_exceeded",
    "validate_date_range",
    "is_concurrent_session_limit_reached",
    "is_device_limit_reached",
    "compute_period_start",
    "is_fup_usage_exceeded",
    "validate_extension_minutes",
]

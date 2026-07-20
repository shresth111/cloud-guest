"""Pure, side-effect-free validation for the Guest domain.

Mirrors ``app.domains.voucher.validators``/``app.domains.captive_portal
.validators``'s identical discipline: no I/O, just "is this a legal input
or transition" checks the service layer calls before touching the database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import (
    BYTES_PER_MB,
    GUEST_SESSION_STATUS_TRANSITIONS,
    NAS_STATUS_TRANSITIONS,
    GuestSessionStatus,
    NasStatus,
    QuotaPeriodType,
)
from .exceptions import (
    InvalidAnalyticsDateRangeError,
    InvalidExtensionMinutesError,
    InvalidNasStatusTransitionError,
    InvalidSessionStatusTransitionError,
)
from .models import GuestSession


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
    ``count_devices_for_guest`` has already fetched ``device_count`` --
    mirrors ``is_concurrent_session_limit_reached``'s identical shape and
    ``>=`` (not ``>``) reasoning: a guest with exactly ``limit`` devices
    has already reached it."""
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


__all__ = [
    "normalize_mac_address",
    "normalize_identifier",
    "validate_session_status_transition",
    "validate_nas_status_transition",
    "is_session_timed_out",
    "is_quota_exceeded",
    "validate_date_range",
    "is_concurrent_session_limit_reached",
    "is_device_limit_reached",
    "compute_period_start",
    "is_fup_usage_exceeded",
    "validate_extension_minutes",
]

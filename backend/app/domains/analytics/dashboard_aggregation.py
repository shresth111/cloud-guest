"""Pure, side-effect-free computation helpers for BE-012 Part 2's dashboards.

Mirrors ``aggregation.py``'s own discipline (BE-012 Part 1): every function
here is plain, synchronous, dependency-free Python operating on already-
fetched values -- never a database call itself -- so it is exercised in
``tests/unit/test_analytics_dashboards.py`` against hand-rolled inputs, no
Postgres/Redis involved. The real SQL aggregate queries these functions
consume live in ``repository.py``; the split keeps "what do we ask the
database for" and "what do we do with the numbers once we have them"
independently testable, the same seam ``aggregation.py``/``repository.py``
already establish for Part 1.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from .dashboard_schemas import (
    AuthMethodBreakdownItem,
    DeviceBreakdownItem,
    DeviceBreakdownResponse,
)
from .health_score import GrowthDirection


class TrendDirection(StrEnum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    FLAT = "flat"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class GrowthPoint:
    """One metric's growth comparison between two ``AnalyticsSnapshot``
    ``metrics`` values -- "day-over-day" or "month-over-month" is purely a
    function of how far apart the two snapshots the caller supplies are; this
    function itself is granularity-agnostic."""

    metric: str
    current_value: float
    previous_value: float | None
    delta: float | None
    delta_percent: float | None
    direction: TrendDirection


def compute_growth(
    *, metric: str, current: float, previous: float | None
) -> GrowthPoint:
    """Compares ``current`` against ``previous`` (``None`` when no earlier
    snapshot exists yet -- e.g. an organization's very first day on the
    platform). Never divides by zero: a ``previous`` of exactly ``0`` reports
    ``delta_percent=None`` (undefined) rather than an infinite/fabricated
    percentage, while ``delta`` (the raw difference) is still reported."""
    if previous is None:
        return GrowthPoint(
            metric=metric,
            current_value=current,
            previous_value=None,
            delta=None,
            delta_percent=None,
            direction=TrendDirection.UNKNOWN,
        )
    delta = current - previous
    delta_percent = (delta / previous * 100.0) if previous != 0 else None
    if delta > 0:
        direction = TrendDirection.INCREASING
    elif delta < 0:
        direction = TrendDirection.DECREASING
    else:
        direction = TrendDirection.FLAT
    return GrowthPoint(
        metric=metric,
        current_value=current,
        previous_value=previous,
        delta=delta,
        delta_percent=delta_percent,
        direction=direction,
    )


def growth_direction_to_health_direction(direction: TrendDirection) -> GrowthDirection:
    """Bridges this module's own general-purpose ``TrendDirection`` into
    ``health_score.GrowthDirection`` -- same three-way sign, different enum,
    since the health-score module intentionally has no dependency on this
    one (it only needs the *sign*, not the full growth-point shape)."""
    mapping = {
        TrendDirection.INCREASING: GrowthDirection.GROWING,
        TrendDirection.DECREASING: GrowthDirection.DECLINING,
        TrendDirection.FLAT: GrowthDirection.FLAT,
        TrendDirection.UNKNOWN: GrowthDirection.UNKNOWN,
    }
    return mapping[direction]


def sum_metric_across_snapshots(
    snapshots: Sequence[Mapping[str, object]], metric_key: str
) -> float:
    """Sums one numeric field out of a list of ``AnalyticsSnapshot.metrics``
    dicts -- the real mechanism behind "weekly/monthly visitors from daily
    snapshots" (BE-012 Part 2's Location Dashboard): summing already-computed
    daily rollups, never re-querying raw ``GuestSession`` rows for the wider
    window (that would defeat the entire point of the snapshot table Part 1
    built). Missing/non-numeric values are treated as ``0`` -- a snapshot
    whose metrics dict is missing a key (should not happen for a
    successfully-computed row, but is not this function's job to validate)
    contributes nothing rather than raising."""
    total = 0.0
    for snapshot_metrics in snapshots:
        value = snapshot_metrics.get(metric_key, 0)
        if isinstance(value, int | float):
            total += value
    return total


def average_metric_across_snapshots(
    snapshots: Sequence[Mapping[str, object]], metric_key: str
) -> float | None:
    """Same idea as :func:`sum_metric_across_snapshots` but for a metric that
    should be averaged (not summed) across the window -- e.g. an "average
    session duration" figure that is itself already an average per day,
    where summing across days would not be meaningful (unlike a count, which
    is additive). Ignores ``None``/non-numeric entries; returns ``None`` if
    every snapshot lacks the metric (rather than fabricating ``0``)."""
    values = [
        snapshot_metrics.get(metric_key)
        for snapshot_metrics in snapshots
        if isinstance(snapshot_metrics.get(metric_key), int | float)
    ]
    if not values:
        return None
    return sum(values) / len(values)


# ============================================================================
# BE-012 Part 3: Router + Network + Guest + Authentication Analytics --
# additional pure computation helpers, same discipline as everything above
# (no I/O, no database call, exercised against hand-rolled fixtures in
# ``tests/unit/test_analytics_router_network_guest_auth.py``).
# ============================================================================


def compute_guest_retention_rate(
    *,
    current_guest_ids: set[uuid.UUID],
    previous_guest_ids: set[uuid.UUID],
) -> tuple[float | None, int]:
    """Guest Retention, defined exactly as: **the percentage of guests seen
    in the immediately preceding period (of equal length) who were *also*
    seen again in the current period** --
    ``retained_count = |current_guest_ids ∩ previous_guest_ids|``,
    ``retention_rate_percent = retained_count / |previous_guest_ids| * 100``.

    Returns ``(retention_rate_percent, retained_count)``. The rate is
    ``None`` (never a fabricated ``0.0``) when ``previous_guest_ids`` is
    empty -- there were no guests in the prior period to have retained in
    the first place, an undefined ratio, not a real zero (mirrors
    ``compute_growth``'s own "never divide by zero, report ``None``
    instead" discipline)."""
    retained = current_guest_ids & previous_guest_ids
    if not previous_guest_ids:
        return None, 0
    return (len(retained) / len(previous_guest_ids)) * 100.0, len(retained)


def compute_average_speed_bytes_per_second(
    *, total_bytes: int, window_start: datetime, window_end: datetime
) -> float | None:
    """``total_bytes / elapsed_seconds`` over ``[window_start, window_end]``
    -- Network Analytics' "Average Speed". ``None`` (not a fabricated ``0``
    or an infinite value) for a zero-or-negative-width window, which cannot
    meaningfully have a rate."""
    duration_seconds = (window_end - window_start).total_seconds()
    if duration_seconds <= 0:
        return None
    return total_bytes / duration_seconds


class _UserAgentBreakdownLike(Protocol):
    """Structural shape :func:`device_breakdown_response` reads --
    satisfied by the real ``AnalyticsRepository.UserAgentBreakdown``
    dataclass, again without an import dependency on ``repository.py``."""

    sessions_total: int
    sessions_with_user_agent: int
    by_os: list[tuple[str, int]]
    by_browser: list[tuple[str, int]]
    by_device_type: list[tuple[str, int]]


def build_auth_method_breakdown(
    rows: list[tuple[str, bool, int]],
) -> list[AuthMethodBreakdownItem]:
    """Reduces a real ``GROUP BY (auth_method, success)`` SQL result
    (``AnalyticsRepository.get_auth_method_breakdown``) into one
    ``AuthMethodBreakdownItem`` per distinct ``auth_method`` -- shared by
    both BE-012 Part 2's dashboards (``dashboard_service.py``) and Part 3's
    Authentication Analytics (``domain_analytics_service.py``), so the two
    never define two subtly-different notions of "successful/failed
    attempts per auth method"."""
    by_method: dict[str, dict[str, int]] = {}
    for auth_method, success, count in rows:
        entry = by_method.setdefault(auth_method, {"success": 0, "failure": 0})
        if success:
            entry["success"] += count
        else:
            entry["failure"] += count
    return [
        AuthMethodBreakdownItem(
            auth_method=auth_method,
            successful_attempts=counts["success"],
            failed_attempts=counts["failure"],
        )
        for auth_method, counts in sorted(by_method.items())
    ]


def device_breakdown_response(
    breakdown: _UserAgentBreakdownLike,
) -> DeviceBreakdownResponse:
    """Maps a real ``AnalyticsRepository.UserAgentBreakdown`` (the User-Agent
    classification's own SQL-computed result) into the API response shape --
    shared by Part 2's Location Dashboard and Part 3's Guest Analytics
    (``domain_analytics_service.py``), so both compose the *exact same*
    classification query and the *exact same* response mapping, never a
    second, possibly-inconsistent version of either."""
    message = None
    if breakdown.sessions_total and not breakdown.sessions_with_user_agent:
        message = (
            "No sessions in this window captured a User-Agent header (all "
            "predate this capture, or every guest device omitted it)."
        )
    elif not breakdown.sessions_total:
        message = "No guest sessions in this window."
    return DeviceBreakdownResponse(
        available=True,
        sessions_total=breakdown.sessions_total,
        sessions_with_data=breakdown.sessions_with_user_agent,
        by_os=[
            DeviceBreakdownItem(label=label, session_count=count)
            for label, count in breakdown.by_os
        ],
        by_browser=[
            DeviceBreakdownItem(label=label, session_count=count)
            for label, count in breakdown.by_browser
        ],
        by_device_type=[
            DeviceBreakdownItem(label=label, session_count=count)
            for label, count in breakdown.by_device_type
        ],
        message=message,
    )


@dataclass(frozen=True, slots=True)
class PeakBandwidthPoint:
    """One time-bucket's total bandwidth -- the winner of
    :func:`compute_peak_bandwidth`'s "highest bucket" search."""

    bucket_start: datetime
    bucket_end: datetime
    bytes_total: float


def compute_peak_bandwidth(
    buckets: Sequence[tuple[datetime, datetime, float]],
) -> PeakBandwidthPoint | None:
    """Network Analytics' "Peak Bandwidth": the single highest-total-bytes
    bucket among ``buckets`` -- each bucket is one already-computed
    ``AnalyticsSnapshot`` (``ORG_DAILY_SUMMARY``) row's own
    ``[period_start, period_end)`` window and its ``total_bandwidth_bytes``
    value (see ``domain_analytics_service.py``'s Network Analytics
    docstring for exactly which snapshots feed this and why this is
    "bytes transferred within the busiest already-computed bucket," never an
    instantaneous bits-per-second throughput rate -- no such rate exists
    anywhere in this codebase's real data, since neither ``GuestSession``
    nor ``RouterHealthSnapshot`` records a point-in-time rate, only
    cumulative byte counters).

    Returns ``None`` for an empty ``buckets`` sequence (no snapshot history
    exists yet, e.g. before Celery's aggregation pipeline has ever run) --
    never a fabricated zero-bandwidth peak."""
    if not buckets:
        return None
    bucket_start, bucket_end, bytes_total = max(buckets, key=lambda bucket: bucket[2])
    return PeakBandwidthPoint(
        bucket_start=bucket_start, bucket_end=bucket_end, bytes_total=bytes_total
    )


__all__ = [
    "TrendDirection",
    "GrowthPoint",
    "compute_growth",
    "growth_direction_to_health_direction",
    "sum_metric_across_snapshots",
    "average_metric_across_snapshots",
    "compute_guest_retention_rate",
    "compute_average_speed_bytes_per_second",
    "PeakBandwidthPoint",
    "compute_peak_bandwidth",
    "build_auth_method_breakdown",
    "device_breakdown_response",
]

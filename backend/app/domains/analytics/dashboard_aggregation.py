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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

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


__all__ = [
    "TrendDirection",
    "GrowthPoint",
    "compute_growth",
    "growth_direction_to_health_direction",
    "sum_metric_across_snapshots",
    "average_metric_across_snapshots",
]

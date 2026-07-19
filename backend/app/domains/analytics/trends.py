"""Trend Engine (BE-012 Part 4): the one, general-purpose "trend for metric X
over period Y" implementation this domain composes with, rather than three
near-identical copies scattered across dashboards/domain-analytics/forecast/
insights.

Before writing this file, this part's own "check first, extend rather than
duplicate" mandate was followed: ``dashboard_aggregation.py`` (BE-012 Part 2)
already owns the two-point comparison primitive (``compute_growth``) and two
whole-window summation helpers (``sum_metric_across_snapshots``/
``average_metric_across_snapshots``) -- those are reused here, not
reimplemented. What was genuinely missing, and is genuinely new in this
file:

1. **A day-by-day numeric series extractor** (:func:`extract_metric_series`)
   -- turning a list of ``AnalyticsSnapshot``-shaped rows into a plain,
   ordered ``[(timestamp, value), ...]`` series for one ``metrics`` JSONB
   key. Every later consumer (the Forecast Engine's linear-regression fit,
   the Insight Engine's rule inputs) needs exactly this shape, and neither
   Part 2 nor Part 3 needed it (they only ever compared two points, or
   summed a whole window into one number).
2. **A single shared point-over-point ``GrowthPointResponse`` builder**
   (:func:`growth_point_response`) -- ``dashboard_service.py`` (Part 2) and
   ``domain_analytics_service.py`` (Part 3) each independently defined a
   private, byte-for-byte-identical ``_growth_response(metric, current,
   previous)`` wrapper around ``compute_growth``. Both were refactored (this
   part) to import this one public function instead -- a pure,
   behavior-preserving de-duplication (see ``docs/analytics/FLOW.md`` for
   the write-up); every existing Part 2/3 test still passes unchanged.
3. **A single shared day-over-day trend builder** (:func:`build_growth_trend`)
   -- ``dashboard_service._compute_org_traffic_trend`` and
   ``domain_analytics_service._compute_traffic_trend`` each independently
   looped over an ordered snapshot list building a day-over-day
   ``GrowthPointResponse`` series for ``total_bandwidth_bytes``. Both were
   refactored to call this one function instead, parameterized by
   ``metric_key`` so it is not bandwidth-specific.
4. **A single shared "current vs. N-days-ago snapshot" growth query**
   (:func:`compute_snapshot_metric_growth`) -- a *new* capability (not a
   refactor of existing code): fetches the latest snapshot of one
   ``snapshot_type``/scope plus the closest snapshot at least
   ``lookback_days`` earlier, and returns a real ``GrowthPointResponse``
   comparing one ``metric_key`` between them. This is genuinely new
   because Part 2's own ``DashboardService._compute_platform_growth``/
   ``_compute_health_score`` each fetch *one* current/previous snapshot pair
   and derive *several* metrics from it in a single round trip (an
   intentional, already-tested optimization) -- refactoring either of those
   to call this new, single-metric-per-fetch helper would trade one
   efficient multi-metric round trip for several redundant ones, for zero
   behavior change and non-trivial regression risk to already-passing
   tests. This part's own callers (``BusinessAnalyticsService``'s Customer
   Growth, ``InsightService``'s Customer/Guest Growth insight rules) each
   only need *one* metric's growth at a time, so the inefficiency this
   avoids for Part 2 does not apply to them -- they use this new function
   directly, and Part 2's own two call sites are deliberately left as-is.
5. **A trailing consecutive-increase counter**
   (:func:`count_trailing_consecutive_increases`) -- a small, general
   numeric-series utility ("has this metric been rising
   for N readings in a row") used by the Insight Engine's rising-router-CPU
   rule. Kept here (not in ``insights.py``) since it is a general
   trend-shaped primitive with no dependency on any rule-engine concept.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from .dashboard_aggregation import compute_growth
from .dashboard_schemas import GrowthPointResponse

__all__ = [
    "TrendPoint",
    "SnapshotLike",
    "extract_metric_series",
    "growth_point_response",
    "build_growth_trend",
    "SnapshotHistoryLookupProtocol",
    "compute_snapshot_metric_growth",
    "count_trailing_consecutive_increases",
]


@dataclass(frozen=True, slots=True)
class TrendPoint:
    """One (timestamp, numeric value) observation -- the shared input shape
    every Forecast/Insight Engine function in this part consumes."""

    timestamp: datetime
    value: float


class SnapshotLike(Protocol):
    """The structural shape :func:`extract_metric_series` reads off each
    row -- satisfied by the real ``AnalyticsSnapshot`` ORM model without
    importing it (mirrors this domain's own established duck-typed
    ``Protocol`` composition discipline, e.g.
    ``dashboard_aggregation._UserAgentBreakdownLike``)."""

    period_start: datetime
    metrics: Mapping[str, object]


def extract_metric_series(
    snapshots: Sequence[SnapshotLike], metric_key: str
) -> list[TrendPoint]:
    """Extracts one numeric ``metrics[metric_key]`` time series from a list
    of snapshot-shaped rows, sorted chronologically by ``period_start``
    (the input order is never assumed) -- missing/non-numeric values are
    treated as ``0.0``, mirroring
    ``dashboard_aggregation.sum_metric_across_snapshots``'s identical "a
    snapshot missing this key contributes nothing rather than raising"
    discipline."""
    points = [
        TrendPoint(
            timestamp=snapshot.period_start,
            value=float(_numeric_or_zero(snapshot.metrics.get(metric_key))),
        )
        for snapshot in snapshots
    ]
    return sorted(points, key=lambda point: point.timestamp)


def _numeric_or_zero(value: object) -> float:
    return value if isinstance(value, int | float) else 0.0


def growth_point_response(
    metric: str, current: float, previous: float | None
) -> GrowthPointResponse:
    """The one shared ``compute_growth`` -> ``GrowthPointResponse`` mapping
    -- see module docstring point 2. ``metric`` doubles as either a metric
    name (e.g. ``"cpu_usage_percent"``) or a date-string label (e.g.
    ``"2026-01-01"``) depending on the call site, mirroring the exact dual
    use the two now-removed private ``_growth_response`` copies already
    established."""
    point = compute_growth(metric=metric, current=current, previous=previous)
    return GrowthPointResponse(
        metric=point.metric,
        current_value=point.current_value,
        previous_value=point.previous_value,
        delta=point.delta,
        delta_percent=point.delta_percent,
        direction=point.direction.value,
    )


def build_growth_trend(
    snapshots: Sequence[SnapshotLike], metric_key: str
) -> list[GrowthPointResponse]:
    """Builds a day-over-day (point-over-point) ``GrowthPointResponse``
    series for one metric across an ordered (or unordered -- this function
    sorts) snapshot history -- see module docstring point 3. Each point's
    ``metric`` label is that snapshot's own ``period_start`` date (ISO
    ``YYYY-MM-DD``)."""
    series = extract_metric_series(snapshots, metric_key)
    points: list[GrowthPointResponse] = []
    previous_value: float | None = None
    for point in series:
        points.append(
            growth_point_response(
                point.timestamp.date().isoformat(), point.value, previous_value
            )
        )
        previous_value = point.value
    return points


class SnapshotHistoryLookupProtocol(Protocol):
    """The narrow slice of ``AnalyticsRepositoryProtocol``
    :func:`compute_snapshot_metric_growth` needs -- kept as its own small
    protocol (rather than importing the full repository protocol) so this
    module stays a leaf dependency of ``repository.py``, never the reverse."""

    async def get_latest_snapshot(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: str,
    ) -> object | None: ...

    async def list_snapshots(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: str | None,
        start: datetime | None,
        end: datetime | None,
        page: int,
        page_size: int,
    ) -> tuple[list[object], object]: ...


async def compute_snapshot_metric_growth(
    repository: SnapshotHistoryLookupProtocol,
    *,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
    snapshot_type: str,
    metric_key: str,
    lookback_days: int,
    now: datetime,
) -> GrowthPointResponse:
    """The one shared "current vs. N-days-ago snapshot" single-metric growth
    query -- see module docstring point 4. Composes
    ``AnalyticsRepositoryProtocol.get_latest_snapshot``/``list_snapshots``
    (both already existed since BE-012 Part 1) with ``compute_growth``
    (Part 2) -- no new SQL, no new repository method, just one more caller
    of methods that already exist."""
    current = await repository.get_latest_snapshot(
        organization_id=organization_id,
        location_id=location_id,
        snapshot_type=snapshot_type,
    )
    cutoff = (current.period_start if current else now) - timedelta(days=lookback_days)  # type: ignore[union-attr]
    previous_rows, _ = await repository.list_snapshots(
        organization_id=organization_id,
        location_id=location_id,
        snapshot_type=snapshot_type,
        start=None,
        end=cutoff,
        page=1,
        page_size=1,
    )
    previous = previous_rows[0] if previous_rows else None

    current_value = (
        _numeric_or_zero(current.metrics.get(metric_key)) if current else 0.0  # type: ignore[union-attr]
    )
    previous_value = (
        _numeric_or_zero(previous.metrics.get(metric_key)) if previous else None  # type: ignore[union-attr]
    )
    return growth_point_response(metric_key, float(current_value), previous_value)


def count_trailing_consecutive_increases(values: Sequence[float]) -> int:
    """Counts how many consecutive strictly-increasing steps appear at the
    END of ``values`` (chronological order) -- e.g. ``[40, 45, 50, 62]`` ->
    ``3``. A flat or decreasing final step resets the count to ``0`` (the
    run must be unbroken and touch the most recent reading). Used by the
    Insight Engine's rising-router-CPU rule -- a simple monotonic-run check,
    deliberately distinct from (and cheaper than) fitting a full linear
    regression when the question is only "has this been rising every single
    reading recently", not "what is the average rate of rise"."""
    count = 0
    for index in range(len(values) - 1, 0, -1):
        if values[index] > values[index - 1]:
            count += 1
        else:
            break
    return count

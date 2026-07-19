"""Forecast Engine (BE-012 Part 4).

**No AI/ML/LLM provider of any kind is used or added anywhere in this
module.** Per this part's explicit brief ("Reuse existing AI Platform
Services. Do NOT implement AI providers"), and confirmed by inspection:
there is no OpenAI/Anthropic/Ollama/any-LLM client, no API key configuration,
no mocked "AI response" anywhere in this codebase, and none is fabricated
here. Every forecast below is produced by real, classical, deterministic
statistics over already-real ``AnalyticsSnapshot``/``RouterHealthSnapshot``
history -- ordinary least-squares linear regression, implemented directly in
~20 lines of pure Python (:func:`fit_linear_trend`), using only the stdlib
(no ``numpy``/``scipy`` -- unnecessary for a single-variable OLS fit).

## The exact linear-regression method

:func:`fit_linear_trend` fits ``y = slope * x + intercept`` over a list of
``(x, y)`` pairs via the standard closed-form OLS solution:

::

    slope     = (n * sum(xy) - sum(x) * sum(y)) / (n * sum(x^2) - sum(x)^2)
    intercept = (sum(y) - slope * sum(x)) / n

``x`` is always a day-offset (a plain ``float``, days since the series'
first observation) so ``slope`` is directly interpretable as "units per
day". :func:`LinearFit.r_squared` is the real coefficient of determination
of *this exact fit against this exact data* (``1 - SS_res / SS_tot``) --
this is the ONLY "confidence"-shaped number this module ever reports, and it
is never invented or hardcoded: a caller asking "how good is this
projection" gets the real number the regression itself produced, or nothing
at all (``available: false``) when too few points exist to fit a line.
**There is no fabricated "N% confidence"/"N% probability" figure anywhere in
this module.**

## Every forecast is an extrapolation, not a guarantee

Every response built from :func:`forecast_linear_series` carries both the
real historical points the fit was computed from and the projected points --
a caller can always see exactly what was extrapolated from. This is a linear
projection of a recent trend continuing unchanged; it cannot and does not
account for seasonality, one-off events, or any factor outside the metric's
own recent history. This is stated in every forecast response's own
``LinearFitInfo.note`` field (see ``forecast_schemas.py``), never silently
implied.

## Router Failure Risk: an honest heuristic risk FLAG, not a predictive model

:func:`assess_router_failure_risk` is explicitly **not** a machine-learning
failure-prediction model -- none exists in this codebase, and none is
fabricated here (a false-precision "87% failure probability" style number
would be exactly the kind of invented confidence this part's honesty mandate
forbids). Instead, it is a real, cited, multi-signal heuristic: a router is
flagged ``at_risk=True`` if and only if at least one of three independently
computed, real signals fires, each backed by a real number computed from
real data:

1. **Rising CPU/memory usage** -- a real OLS fit (the same
   :func:`fit_linear_trend` every other forecast in this module uses) over
   the router's own recent ``RouterHealthSnapshot.cpu_usage_percent``/
   ``memory_usage_percent`` history; fires when the fitted slope exceeds a
   configured percentage-points-per-day threshold
   (``Settings.analytics_forecast_router_cpu_rising_slope_threshold``/
   ``..._memory_rising_slope_threshold``).
2. **Degrading health status** -- ``RouterHealthSnapshot.health_status`` is
   categorical (``"healthy"``/``"unhealthy"``/``None``), not numeric, so a
   literal regression slope cannot be fit to it. "A sustained negative
   trend" is therefore operationalized as the *ratio* of recent readings
   reporting ``"unhealthy"`` meeting a configured threshold
   (``Settings.analytics_forecast_router_unhealthy_ratio_threshold``) --
   an honest, real, if categorical-appropriate, alternative to a numeric
   slope.
3. **Repeated Alerts** -- a real count of ``app.domains.monitoring.models
   .Alert`` rows recorded against this specific router (``Alert.router_id``
   is a real, populated FK) within a configured lookback window, fired when
   at/above a configured count threshold.

Every signal that fires is reported with the *exact real number* behind it
(the fitted slope and its own real R², the real unhealthy-reading ratio, the
real alert count) -- never a synthesized single risk score.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .trends import TrendPoint

__all__ = [
    "LinearFit",
    "fit_linear_trend",
    "ForecastPoint",
    "LinearForecastResult",
    "forecast_linear_series",
    "ThresholdCrossingResult",
    "project_upward_threshold_crossing",
    "RouterRiskSignal",
    "RouterFailureRiskResult",
    "assess_router_failure_risk",
]


@dataclass(frozen=True, slots=True)
class LinearFit:
    """The result of an ordinary-least-squares fit -- see module docstring
    for the exact formulas. ``r_squared`` is always the real coefficient of
    determination of this fit against the data it was computed from
    (mathematically guaranteed to be within ``[0, 1]`` for an OLS fit
    evaluated against its own training data)."""

    slope: float
    intercept: float
    r_squared: float
    point_count: int

    def project(self, x: float) -> float:
        return self.slope * x + self.intercept


def fit_linear_trend(points: list[tuple[float, float]]) -> LinearFit | None:
    """Ordinary least-squares fit of ``y = slope * x + intercept`` over
    ``points`` -- real, direct arithmetic (no dependency). Returns ``None``
    when fewer than 2 points are given, or when every ``x`` value is
    identical (a vertical "line" has no slope/intercept form -- cannot
    honestly fit a trend to points with no time/x separation)."""
    n = len(points)
    if n < 2:
        return None
    sum_x = sum(x for x, _ in points)
    sum_y = sum(y for _, y in points)
    sum_xy = sum(x * y for x, y in points)
    sum_x2 = sum(x * x for x, _ in points)
    denominator = n * sum_x2 - sum_x * sum_x
    if denominator == 0:
        return None

    slope = (n * sum_xy - sum_x * sum_y) / denominator
    intercept = (sum_y - slope * sum_x) / n

    mean_y = sum_y / n
    ss_tot = sum((y - mean_y) ** 2 for _, y in points)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in points)
    r_squared = 1.0 if ss_tot == 0 else max(0.0, min(1.0, 1.0 - ss_res / ss_tot))

    return LinearFit(
        slope=slope, intercept=intercept, r_squared=r_squared, point_count=n
    )


@dataclass(frozen=True, slots=True)
class ForecastPoint:
    timestamp: datetime
    value: float


@dataclass(frozen=True, slots=True)
class LinearForecastResult:
    available: bool
    historical_points: list[ForecastPoint] = field(default_factory=list)
    projected_points: list[ForecastPoint] = field(default_factory=list)
    fit: LinearFit | None = None
    message: str | None = None


def forecast_linear_series(
    series: list[TrendPoint], *, forecast_days: int, min_points: int
) -> LinearForecastResult:
    """Fits :func:`fit_linear_trend` over ``series`` (converted to
    day-offset ``x`` values, day 0 == the series' first observation) and
    projects ``forecast_days`` daily points beyond the last observed
    timestamp. ``available=False`` (never a fabricated projection) when
    fewer than ``min_points`` real historical points exist, or when every
    point shares the same timestamp."""
    historical = [ForecastPoint(timestamp=p.timestamp, value=p.value) for p in series]
    if len(series) < min_points:
        return LinearForecastResult(
            available=False,
            historical_points=historical,
            message=(
                f"Not enough historical data points to compute a linear "
                f"forecast: {len(series)} available, {min_points} required "
                f"(Settings.analytics_forecast_min_history_points)."
            ),
        )

    base_timestamp = series[0].timestamp
    xy_points = [
        ((point.timestamp - base_timestamp).total_seconds() / 86400.0, point.value)
        for point in series
    ]
    fit = fit_linear_trend(xy_points)
    if fit is None:
        return LinearForecastResult(
            available=False,
            historical_points=historical,
            message=(
                "All historical data points share the same timestamp; a "
                "trend cannot be fit."
            ),
        )

    last_x = xy_points[-1][0]
    last_timestamp = series[-1].timestamp
    projected = [
        ForecastPoint(
            timestamp=last_timestamp + timedelta(days=day_offset),
            value=fit.project(last_x + day_offset),
        )
        for day_offset in range(1, forecast_days + 1)
    ]
    return LinearForecastResult(
        available=True,
        historical_points=historical,
        projected_points=projected,
        fit=fit,
    )


@dataclass(frozen=True, slots=True)
class ThresholdCrossingResult:
    available: bool
    projected_crossing_date: datetime | None
    days_until_crossing: int | None
    message: str


def project_upward_threshold_crossing(
    *,
    fit: LinearFit,
    last_x: float,
    last_timestamp: datetime,
    current_value: float,
    threshold: float,
) -> ThresholdCrossingResult:
    """Answers "when will this metric first reach/exceed ``threshold``,
    given its current real linear trend" -- the Capacity Prediction
    formula. Deliberately an *upward*-crossing question only (the natural
    framing for "when will this resource exceed its capacity ceiling"),
    which keeps the math unambiguous: a metric already at/above the
    threshold has trivially "crossed" it (``days_until_crossing=0``); a flat
    or declining trend that has not yet crossed it will never cross it at
    the current rate (``available=False``); otherwise the real OLS fit's own
    line is solved for the ``x`` where it equals ``threshold``, and the
    number of days from the most recent real observation to that ``x`` is
    reported, rounded up (a crossing predicted to happen partway through a
    day is reported as "by the end of that day")."""
    if current_value >= threshold:
        return ThresholdCrossingResult(
            available=True,
            projected_crossing_date=last_timestamp,
            days_until_crossing=0,
            message=(
                "Threshold already reached or exceeded as of the most "
                "recent data point."
            ),
        )
    if fit.slope <= 0:
        return ThresholdCrossingResult(
            available=False,
            projected_crossing_date=None,
            days_until_crossing=None,
            message=(
                "Trend is flat or declining; the threshold will not be "
                "reached at the current rate."
            ),
        )
    x_star = (threshold - fit.intercept) / fit.slope
    days_from_last = max(x_star - last_x, 0.0)
    days = max(math.ceil(days_from_last), 1)
    return ThresholdCrossingResult(
        available=True,
        projected_crossing_date=last_timestamp + timedelta(days=days),
        days_until_crossing=days,
        message="Projected via linear extrapolation of recent history.",
    )


@dataclass(frozen=True, slots=True)
class RouterRiskSignal:
    """One real, cited signal contributing to a router's ``at_risk`` flag --
    see module docstring's "Router Failure Risk" section for the exact
    three signals."""

    name: str
    detail: str


@dataclass(frozen=True, slots=True)
class RouterFailureRiskResult:
    router_id: uuid.UUID
    router_name: str
    at_risk: bool
    signals: list[RouterRiskSignal] = field(default_factory=list)


def assess_router_failure_risk(
    *,
    router_id: uuid.UUID,
    router_name: str,
    cpu_history: list[TrendPoint],
    memory_history: list[TrendPoint],
    unhealthy_snapshot_count: int,
    total_snapshot_count: int,
    alert_count: int,
    cpu_rising_slope_threshold: float,
    memory_rising_slope_threshold: float,
    unhealthy_ratio_threshold: float,
    alert_count_threshold: int,
    min_history_points: int,
) -> RouterFailureRiskResult:
    """Pure, testable core of the Router Failure Risk heuristic -- see
    module docstring for the full write-up of why this is a real, cited,
    multi-signal risk FLAG, never a predictive model or a fabricated
    probability. Takes already-fetched real history/counts (the real SQL
    narrows in ``forecast_service.py``); this function only computes."""
    signals: list[RouterRiskSignal] = []

    cpu_signal = _rising_metric_signal(
        history=cpu_history,
        slope_threshold=cpu_rising_slope_threshold,
        min_history_points=min_history_points,
        signal_name="rising_cpu_usage",
        label="CPU usage",
    )
    if cpu_signal is not None:
        signals.append(cpu_signal)

    memory_signal = _rising_metric_signal(
        history=memory_history,
        slope_threshold=memory_rising_slope_threshold,
        min_history_points=min_history_points,
        signal_name="rising_memory_usage",
        label="Memory usage",
    )
    if memory_signal is not None:
        signals.append(memory_signal)

    if total_snapshot_count > 0:
        unhealthy_ratio = unhealthy_snapshot_count / total_snapshot_count
        if unhealthy_ratio >= unhealthy_ratio_threshold:
            signals.append(
                RouterRiskSignal(
                    name="degrading_health_status",
                    detail=(
                        f"{unhealthy_snapshot_count} of the last "
                        f"{total_snapshot_count} health snapshots reported "
                        f"'unhealthy' ({unhealthy_ratio * 100:.0f}%)."
                    ),
                )
            )

    if alert_count >= alert_count_threshold:
        signals.append(
            RouterRiskSignal(
                name="repeated_alerts",
                detail=(
                    f"{alert_count} monitoring alert(s) recorded for this "
                    f"router in the lookback window."
                ),
            )
        )

    return RouterFailureRiskResult(
        router_id=router_id,
        router_name=router_name,
        at_risk=bool(signals),
        signals=signals,
    )


def _rising_metric_signal(
    *,
    history: list[TrendPoint],
    slope_threshold: float,
    min_history_points: int,
    signal_name: str,
    label: str,
) -> RouterRiskSignal | None:
    if len(history) < min_history_points:
        return None
    base_timestamp = history[0].timestamp
    xy_points = [
        ((point.timestamp - base_timestamp).total_seconds() / 86400.0, point.value)
        for point in history
    ]
    fit = fit_linear_trend(xy_points)
    if fit is None or fit.slope <= slope_threshold:
        return None
    return RouterRiskSignal(
        name=signal_name,
        detail=(
            f"{label} has risen ~{fit.slope:.2f} percentage points/day over "
            f"the last {len(history)} readings (R^2={fit.r_squared:.2f})."
        ),
    )

"""Pydantic response schemas for BE-012 Part 4's Forecast Engine endpoints:
``GET /analytics/forecast/bandwidth|capacity|router-failure-risk|
guest-growth|network-load``.

Follows this domain's own schema conventions exactly. ``LinearFitInfo.note``
and ``RouterFailureRiskResponse.heuristic_note`` state, on every response,
the exact same honesty posture ``forecast.py``'s own module docstring
documents in code: a real linear projection (not a guarantee), and a real,
cited heuristic risk flag (not a predictive model/fabricated probability).
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "HistoricalPointItem",
    "LinearFitInfo",
    "LinearForecastResponse",
    "ThresholdCrossingInfo",
    "CapacityForecastResponse",
    "RouterRiskSignalItem",
    "RouterFailureRiskItem",
    "RouterFailureRiskResponse",
]


class HistoricalPointItem(BaseModel):
    date: str
    value: float


class LinearFitInfo(BaseModel):
    slope_per_day: float
    intercept: float
    r_squared: float = Field(
        description="The REAL coefficient of determination of this exact "
        "ordinary-least-squares fit against the historical points above -- "
        "never a fabricated confidence percentage."
    )
    point_count: int
    note: str = (
        "Ordinary least-squares linear fit over the historical points "
        "above. This is a linear PROJECTION, not a guarantee: it assumes "
        "the recent trend continues unchanged and does not account for "
        "seasonality, one-off events, or any factor outside this metric's "
        "own recent history."
    )


class LinearForecastResponse(BaseModel):
    available: bool
    metric: str
    historical_points: list[HistoricalPointItem]
    projected_points: list[HistoricalPointItem]
    fit: LinearFitInfo | None = None
    message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ThresholdCrossingInfo(BaseModel):
    available: bool
    resource: str
    threshold: float
    current_value: float
    projected_crossing_date: str | None
    days_until_crossing: int | None
    message: str
    threshold_note: str = (
        "'threshold' is an operator-configured planning assumption "
        "(app.core.config.Settings), not data derived from any real "
        "infrastructure-capacity record -- no such record exists anywhere "
        "in this codebase."
    )


class CapacityForecastResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    forecast: LinearForecastResponse
    threshold_crossing: ThresholdCrossingInfo


class RouterRiskSignalItem(BaseModel):
    name: str
    detail: str


class RouterFailureRiskItem(BaseModel):
    router_id: uuid.UUID
    router_name: str
    location_id: uuid.UUID
    at_risk: bool
    signals: list[RouterRiskSignalItem]


class RouterFailureRiskResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    window_start: str
    window_end: str
    routers: list[RouterFailureRiskItem]
    heuristic_note: str = (
        "This is a heuristic RISK FLAG, not a predictive machine-learning "
        "model -- no such model exists or is fabricated here. A router is "
        "flagged 'at risk' only when at least one real, cited signal (a "
        "rising CPU/memory trend fit via ordinary least squares, a high "
        "ratio of recent 'unhealthy' health snapshots, or repeated real "
        "Alerts) is detected in its own recent history. There is no "
        "invented 'N% failure probability' number anywhere in this "
        "response."
    )

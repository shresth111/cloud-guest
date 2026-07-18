"""Lightweight, in-process domain events for the Analytics module.

Plain, frozen dataclasses constructed by ``AnalyticsService`` and logged
synchronously -- mirrors ``app.domains.monitoring.events``/
``app.domains.guest.events``'s identical "simplest thing that could work"
posture: no event bus, no publish/subscribe registry, no async dispatch,
just a typed, self-documenting value object per notable lifecycle moment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AnalyticsSnapshotComputed:
    snapshot_id: uuid.UUID
    snapshot_type: str
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    computation_duration_ms: float | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AnalyticsAggregationBatchCompleted:
    total_organizations: int
    succeeded_organizations: int
    failed_organizations: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AnalyticsAggregationForOrganizationFailed:
    organization_id: uuid.UUID
    error: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "AnalyticsSnapshotComputed",
    "AnalyticsAggregationBatchCompleted",
    "AnalyticsAggregationForOrganizationFailed",
]

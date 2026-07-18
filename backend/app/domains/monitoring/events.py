"""Lightweight, in-process domain events for the Monitoring module.

Plain, frozen dataclasses constructed by ``MonitoringService`` and logged
synchronously by that same service -- mirrors ``app.domains.guest.events``/
``app.domains.wireguard.events``'s identical "simplest thing that could
work" posture: no event bus, no publish/subscribe registry, no async
dispatch, just a typed, self-documenting value object per notable lifecycle
moment. Not part of the public API surface -- nothing outside this module's
own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class HealthCheckExecuted:
    component: str
    status: str
    response_time_ms: float | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ServiceHealthTransitioned:
    component: str
    previous_status: str | None
    new_status: str
    consecutive_failure_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class HeartbeatRecorded:
    component_type: str
    component_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PlatformEventRecorded:
    event_type: str
    category: str
    severity: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AlertTriggered:
    alert_id: uuid.UUID
    rule_id: uuid.UUID
    severity: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AlertAcknowledged:
    alert_id: uuid.UUID
    acknowledged_by_user_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AlertResolved:
    alert_id: uuid.UUID
    auto_resolved: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class NotificationDispatched:
    channel_id: uuid.UUID
    channel_type: str
    alert_id: uuid.UUID
    status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IncidentOpened:
    incident_id: uuid.UUID
    severity: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IncidentStatusChanged:
    incident_id: uuid.UUID
    previous_status: str
    new_status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SlaReportGenerated:
    sla_target_id: uuid.UUID
    achieved_percentage: float
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "HealthCheckExecuted",
    "ServiceHealthTransitioned",
    "HeartbeatRecorded",
    "PlatformEventRecorded",
    "AlertTriggered",
    "AlertAcknowledged",
    "AlertResolved",
    "NotificationDispatched",
    "IncidentOpened",
    "IncidentStatusChanged",
    "SlaReportGenerated",
]

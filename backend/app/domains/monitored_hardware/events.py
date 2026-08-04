"""Lightweight, in-process domain events for the Monitored Hardware
module. Mirrors ``app.domains.network_device.events``'s own identical
design exactly: plain, frozen dataclasses constructed by
``MonitoredHardwareService`` methods and logged directly, synchronously --
no event bus.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class MonitoredHardwareRegistered:
    id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class MonitoredHardwareDeleted:
    id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = ["MonitoredHardwareRegistered", "MonitoredHardwareDeleted"]

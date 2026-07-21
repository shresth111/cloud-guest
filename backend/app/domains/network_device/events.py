"""Lightweight, in-process domain events for the Network Device (NAC)
module. Mirrors ``app.domains.dhcp.events``'s own identical design
exactly: plain, frozen dataclasses constructed by ``NetworkDeviceService``
methods and logged directly, synchronously -- no event bus.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class NetworkDeviceRegistered:
    id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class NetworkDeviceUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class NetworkDeviceComplianceStatusChanged:
    id: uuid.UUID
    previous_status: str
    new_status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class NetworkDeviceDeleted:
    id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "NetworkDeviceRegistered",
    "NetworkDeviceUpdated",
    "NetworkDeviceComplianceStatusChanged",
    "NetworkDeviceDeleted",
]

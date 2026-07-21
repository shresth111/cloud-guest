"""Lightweight, in-process domain events for the Connected Device
Management module.

Mirrors ``app.domains.isp.events``'s own identical design exactly: plain,
frozen dataclasses constructed by ``ConnectedDeviceService`` methods and
logged directly, synchronously -- no event bus, no publish/subscribe
registry, no async dispatch. Not part of the public API surface -- nothing
outside this module's own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ConnectedDeviceDiscovered:
    id: uuid.UUID
    router_id: uuid.UUID
    mac_address: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConnectedDeviceUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConnectedDeviceDisconnected:
    id: uuid.UUID
    router_id: uuid.UUID
    mac_address: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConnectedDeviceDeleted:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ConnectedDeviceAccessRuleApplied:
    id: uuid.UUID
    mac_address: str
    rule_type: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "ConnectedDeviceDiscovered",
    "ConnectedDeviceUpdated",
    "ConnectedDeviceDisconnected",
    "ConnectedDeviceDeleted",
    "ConnectedDeviceAccessRuleApplied",
]

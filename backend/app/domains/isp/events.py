"""Lightweight, in-process domain events for the ISP Management module.

Mirrors ``app.domains.queue_management.events``'s own identical design
exactly: plain, frozen dataclasses constructed by ``IspService`` methods
and logged directly, synchronously -- no event bus, no publish/subscribe
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
class IspLinkCreated:
    link_id: uuid.UUID
    router_id: uuid.UUID
    role: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspLinkUpdated:
    link_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspLinkDeleted:
    link_id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspHealthCheckRecorded:
    link_id: uuid.UUID
    status: str
    latency_ms: float | None
    packet_loss_percentage: float | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspFailoverTriggered:
    router_id: uuid.UUID
    from_link_id: uuid.UUID
    to_link_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspFailbackTriggered:
    router_id: uuid.UUID
    from_link_id: uuid.UUID
    to_link_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "IspLinkCreated",
    "IspLinkUpdated",
    "IspLinkDeleted",
    "IspHealthCheckRecorded",
    "IspFailoverTriggered",
    "IspFailbackTriggered",
]

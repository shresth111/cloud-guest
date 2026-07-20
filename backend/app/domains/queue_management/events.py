"""Lightweight, in-process domain events for the Queue Management Engine
module.

Mirrors ``app.domains.provisioning_engine.events``'s own identical design
exactly: plain, frozen dataclasses constructed by ``QueueManagementService``
methods and logged directly, synchronously -- no event bus, no publish/
subscribe registry, no async dispatch. Not part of the public API surface --
nothing outside this module's own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class QueueProfileCreated:
    profile_id: uuid.UUID
    name: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class QueueAssignmentCreated:
    assignment_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class QueueApplied:
    assignment_id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class QueueRemoved:
    assignment_id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class QueueAssignmentMoved:
    old_assignment_id: uuid.UUID
    new_assignment_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class QueueAssignmentExpired:
    assignment_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "QueueProfileCreated",
    "QueueAssignmentCreated",
    "QueueApplied",
    "QueueRemoved",
    "QueueAssignmentMoved",
    "QueueAssignmentExpired",
]

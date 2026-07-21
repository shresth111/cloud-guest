"""Lightweight, in-process domain events for the VLAN Management module.

Mirrors ``app.domains.isp_routing.events``'s own identical design exactly:
plain, frozen dataclasses constructed by ``VlanService`` methods and
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
class VlanCreated:
    id: uuid.UUID
    router_id: uuid.UUID
    tag: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VlanUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VlanDeleted:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = ["VlanCreated", "VlanUpdated", "VlanDeleted"]

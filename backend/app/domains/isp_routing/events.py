"""Lightweight, in-process domain events for the ISP Routing module.

Mirrors ``app.domains.isp.events``'s own identical design exactly: plain,
frozen dataclasses constructed by ``IspRoutingService`` methods and logged
directly, synchronously -- no event bus, no publish/subscribe registry, no
async dispatch. Not part of the public API surface -- nothing outside this
module's own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class IspRoutingRuleCreated:
    rule_id: uuid.UUID
    router_id: uuid.UUID
    rule_type: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspRoutingRuleUpdated:
    rule_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class IspRoutingRuleDeleted:
    rule_id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "IspRoutingRuleCreated",
    "IspRoutingRuleUpdated",
    "IspRoutingRuleDeleted",
]

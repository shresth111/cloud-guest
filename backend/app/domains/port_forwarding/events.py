"""Lightweight, in-process domain events for the Port Forwarding
Management module.

Mirrors ``app.domains.dhcp.events``'s own identical design exactly:
plain, frozen dataclasses constructed by ``PortForwardingService``
methods and logged directly, synchronously -- no event bus, no
publish/subscribe registry, no async dispatch. Not part of the public API
surface -- nothing outside this module's own ``service.py`` constructs or
reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class PortForwardingRuleCreated:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PortForwardingRuleUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PortForwardingRuleDeleted:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "PortForwardingRuleCreated",
    "PortForwardingRuleUpdated",
    "PortForwardingRuleDeleted",
]

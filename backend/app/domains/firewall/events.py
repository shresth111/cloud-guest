"""Lightweight, in-process domain events for the Firewall Rule Management
module. Mirrors ``app.domains.dhcp.events``'s own identical design
exactly: plain, frozen dataclasses constructed by ``FirewallService``
methods and logged directly, synchronously -- no event bus.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class FirewallRuleCreated:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class FirewallRuleUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class FirewallRuleDeleted:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = ["FirewallRuleCreated", "FirewallRuleUpdated", "FirewallRuleDeleted"]

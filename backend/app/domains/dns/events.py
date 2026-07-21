"""Lightweight, in-process domain events for the DNS Management module.

Mirrors ``app.domains.dhcp.events``'s own identical design exactly: plain,
frozen dataclasses constructed by ``DnsService`` methods and logged
directly, synchronously -- no event bus.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class DnsRecordCreated:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class DnsRecordUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class DnsRecordDeleted:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = ["DnsRecordCreated", "DnsRecordUpdated", "DnsRecordDeleted"]

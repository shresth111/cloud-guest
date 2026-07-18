"""Lightweight, in-process domain events for the WireGuard module.

Plain, frozen dataclasses constructed by ``WireGuardService`` methods and
logged synchronously by that same service -- mirrors
``app.domains.router_agent.events``/``app.domains.router_provisioning
.events``'s identical "simplest thing that could work" posture: no event
bus, no publish/subscribe registry, no async dispatch, just a typed,
self-documenting value object per notable lifecycle moment. Not part of the
public API surface -- nothing outside this module's own ``service.py``
constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class TunnelCreated:
    router_id: uuid.UUID
    peer_id: uuid.UUID
    tunnel_ip_address: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class TunnelRotated:
    router_id: uuid.UUID
    peer_id: uuid.UUID
    rotation_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class TunnelRevoked:
    router_id: uuid.UUID
    peer_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class TunnelHandshakeRecorded:
    router_id: uuid.UUID
    peer_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "TunnelCreated",
    "TunnelRotated",
    "TunnelRevoked",
    "TunnelHandshakeRecorded",
]

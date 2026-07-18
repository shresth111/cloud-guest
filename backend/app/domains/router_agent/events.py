"""Lightweight, in-process domain events for the Router Agent module.

Plain, frozen dataclasses constructed by ``RouterAgentService`` methods and
logged synchronously by that same service -- mirrors
``app.domains.router_provisioning.events``'s identical "simplest thing that
could work" posture: no event bus, no publish/subscribe registry, no async
dispatch, just a typed, self-documenting value object per notable lifecycle
moment. Not part of the public API surface -- nothing outside this module's
own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AgentCredentialIssued:
    router_id: uuid.UUID
    credential_id: uuid.UUID
    rotation_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AgentHeartbeatReceived:
    router_id: uuid.UUID
    previous_status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AgentStatusReported:
    router_id: uuid.UUID
    agent_software_version: str | None
    license_status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AgentActionsClaimed:
    router_id: uuid.UUID
    job_ids: tuple[uuid.UUID, ...]
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AgentActionCompleted:
    router_id: uuid.UUID
    job_id: uuid.UUID
    success: bool
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "AgentCredentialIssued",
    "AgentHeartbeatReceived",
    "AgentStatusReported",
    "AgentActionsClaimed",
    "AgentActionCompleted",
]

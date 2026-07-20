"""Lightweight, in-process domain events for the Provisioning Engine
module.

Mirrors ``app.domains.router_provisioning.events``'s own identical design
exactly: plain, frozen dataclasses constructed by
``ProvisioningEngineService`` methods and logged directly, synchronously --
no event bus, no publish/subscribe registry, no async dispatch. Not part of
the public API surface -- nothing outside this module's own ``service.py``
constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ProvisionJobCreated:
    job_id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionJobStarted:
    job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionStepCompleted:
    job_id: uuid.UUID
    step_type: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionJobSucceeded:
    job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionJobFailed:
    job_id: uuid.UUID
    error_message: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionJobCancelled:
    job_id: uuid.UUID
    reason: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionJobRetried:
    job_id: uuid.UUID
    retry_of_job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ProvisionJobRolledBack:
    job_id: uuid.UUID
    rollback_of_job_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "ProvisionJobCreated",
    "ProvisionJobStarted",
    "ProvisionStepCompleted",
    "ProvisionJobSucceeded",
    "ProvisionJobFailed",
    "ProvisionJobCancelled",
    "ProvisionJobRetried",
    "ProvisionJobRolledBack",
]

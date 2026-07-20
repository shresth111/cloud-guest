"""Lightweight, in-process domain events for the Policy module.

Plain, frozen dataclasses constructed by ``PolicyService`` methods and
logged synchronously -- mirrors every other domain's identical "simplest
thing that could work" posture (no event bus, no publish/subscribe
registry). Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` -- see ``service.py``'s module docstring for this
module's own audit-volume judgment call.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class PolicyCreated:
    policy_id: uuid.UUID
    organization_id: uuid.UUID | None
    policy_type: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PolicyVersionCreated:
    policy_id: uuid.UUID
    version_id: uuid.UUID
    version_number: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PolicyVersionPublished:
    policy_id: uuid.UUID
    version_id: uuid.UUID
    version_number: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PolicyRolledBack:
    policy_id: uuid.UUID
    from_version_id: uuid.UUID | None
    to_version_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PolicyAssignmentCreated:
    assignment_id: uuid.UUID
    policy_id: uuid.UUID
    scope_type: str
    scope_id: uuid.UUID | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PolicyAssignmentDeactivated:
    assignment_id: uuid.UUID
    policy_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "PolicyCreated",
    "PolicyVersionCreated",
    "PolicyVersionPublished",
    "PolicyRolledBack",
    "PolicyAssignmentCreated",
    "PolicyAssignmentDeactivated",
]

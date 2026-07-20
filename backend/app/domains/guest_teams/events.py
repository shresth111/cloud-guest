"""Lightweight, in-process domain events for the Guest Teams module.

Plain, frozen dataclasses constructed by ``GuestTeamService`` methods and
logged synchronously by that same service -- mirrors
``app.domains.guest.events``/``app.domains.voucher.events``'s identical
"simplest thing that could work" posture: no event bus, no publish/
subscribe registry, no async dispatch, just a typed, self-documenting value
object per notable lifecycle moment. Not part of the public API surface --
nothing outside this module's own ``service.py`` constructs or reads these.

Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` -- see ``service.py``'s module docstring for this
module's own audit-volume judgment call (every event here is logged; only
some are also audited).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class GuestTeamCreated:
    team_id: uuid.UUID
    organization_id: uuid.UUID
    team_code: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestMemberJoined:
    team_id: uuid.UUID
    guest_id: uuid.UUID
    is_new_guest: bool
    is_new_membership: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestMemberRemoved:
    team_id: uuid.UUID
    guest_id: uuid.UUID
    reason: str | None
    terminated_session_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestTeamRevoked:
    team_id: uuid.UUID
    reason: str | None
    member_count: int
    terminated_session_count: int
    failed_member_count: int
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "GuestTeamCreated",
    "GuestMemberJoined",
    "GuestMemberRemoved",
    "GuestTeamRevoked",
]

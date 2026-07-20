"""Lightweight, in-process domain events for the Guest module.

Plain, frozen dataclasses constructed by ``GuestService``/
``GuestAnalyticsService``/``RadiusService`` methods and logged synchronously
by that same service -- mirrors ``app.domains.otp.events``/
``app.domains.voucher.events``/``app.domains.captive_portal.events``'s
identical "simplest thing that could work" posture: no event bus, no
publish/subscribe registry, no async dispatch, just a typed,
self-documenting value object per notable lifecycle moment. Not part of the
public API surface -- nothing outside this module's own ``service.py``
constructs or reads these.

Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` -- see ``service.py``'s module docstring for the
audit-volume judgment call (every event here is logged; only some are also
audited).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class GuestLoggedIn:
    guest_id: uuid.UUID
    identifier: str
    auth_method: str
    session_id: uuid.UUID
    is_new_guest: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestLoginFailed:
    guest_id: uuid.UUID | None
    identifier: str
    auth_method: str
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionCreated:
    session_id: uuid.UUID
    guest_id: uuid.UUID
    router_id: uuid.UUID
    auth_method: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionDisconnected:
    session_id: uuid.UUID
    reason: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionTerminated:
    session_id: uuid.UUID
    guest_id: uuid.UUID
    reason: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionExpired:
    session_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionPaused:
    session_id: uuid.UUID
    reason: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionResumed:
    session_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestSessionExtended:
    session_id: uuid.UUID
    additional_minutes: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestBlocked:
    guest_id: uuid.UUID
    reason: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestUnblocked:
    guest_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestConsentRecorded:
    guest_id: uuid.UUID
    captive_portal_config_id: uuid.UUID | None
    terms_version: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RadiusNasRegistered:
    nas_client_id: uuid.UUID
    router_id: uuid.UUID
    nas_identifier: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RadiusNasActivated:
    nas_client_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RadiusNasDisabled:
    nas_client_id: uuid.UUID
    reason: str | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RadiusNasSecretRegenerated:
    nas_client_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RadiusNasUpdated:
    nas_client_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RadiusNasDeleted:
    nas_client_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "GuestLoggedIn",
    "GuestLoginFailed",
    "GuestSessionCreated",
    "GuestSessionDisconnected",
    "GuestSessionTerminated",
    "GuestSessionExpired",
    "GuestSessionPaused",
    "GuestSessionResumed",
    "GuestSessionExtended",
    "GuestBlocked",
    "GuestUnblocked",
    "GuestConsentRecorded",
    "RadiusNasRegistered",
    "RadiusNasActivated",
    "RadiusNasDisabled",
    "RadiusNasSecretRegenerated",
    "RadiusNasUpdated",
    "RadiusNasDeleted",
]

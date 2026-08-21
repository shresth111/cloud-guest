"""Lightweight, in-process domain events for the Captive Portal module.

Plain, frozen dataclasses constructed by ``CaptivePortalService`` methods
and logged synchronously by that same service -- mirrors
``app.domains.otp.events``/``app.domains.voucher.events``'s identical
"simplest thing that could work" posture: no event bus, no publish/
subscribe registry, no async dispatch, just a typed, self-documenting value
object per notable lifecycle moment. Not part of the public API surface --
nothing outside this module's own ``service.py`` constructs or reads these.

Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` in most other domains -- but see ``service.py``'s
module docstring for why this module's own audit-volume judgment call is
"every event here is also audited" (unlike OTP/Voucher's tiering), since
this is low-volume admin configuration, not high-volume guest traffic.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class CaptivePortalConfigCreated:
    config_id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CaptivePortalConfigUpdated:
    config_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CaptivePortalConfigActivated:
    config_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CaptivePortalConfigDeactivated:
    config_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CaptivePortalConfigDeleted:
    config_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CaptivePortalPoweredByRestored:
    """A license downgrade removed the white-label entitlement, and the
    system flipped this organization's ``powered_by_enabled=False`` configs
    back to ``True`` -- see
    ``service.PoweredByAttributionResetService``. One event per reset
    sweep, not per config; the per-config record is the audit entry."""

    organization_id: uuid.UUID
    reset_config_count: int
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "CaptivePortalConfigCreated",
    "CaptivePortalConfigUpdated",
    "CaptivePortalConfigActivated",
    "CaptivePortalConfigDeactivated",
    "CaptivePortalConfigDeleted",
]

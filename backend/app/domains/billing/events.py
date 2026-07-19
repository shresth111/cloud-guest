"""Lightweight, in-process domain events for the Billing module.

Plain, frozen dataclasses constructed by ``service.py`` methods and logged
synchronously by that same service -- mirrors ``app.domains.otp.events``/
``app.domains.wireguard.events``'s identical "simplest thing that could
work" posture: no event bus, no publish/subscribe registry, no async
dispatch, just a typed, self-documenting value object per notable lifecycle
moment. Not part of the public API surface -- nothing outside this module's
own ``service.py`` constructs or reads these.

Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` -- every event here is logged; the license lifecycle
transitions (assign/activate/suspend/upgrade/downgrade/expire/cancel) are
also audited (see ``service.py``'s ``_audit`` calls), since they are exactly
the kind of moderate-volume, admin-attributable action every other domain's
own ``AuditAction`` additions already cover this same way.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class LicenseAssigned:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseActivated:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseSuspended:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseExpired:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseCancelled:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseUpgraded:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    from_plan_id: uuid.UUID | None
    to_plan_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseDowngraded:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    from_plan_id: uuid.UUID | None
    to_plan_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class UsageLimitExceeded:
    organization_id: uuid.UUID
    metric_key: str
    current_value: str
    limit_value: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "LicenseAssigned",
    "LicenseActivated",
    "LicenseSuspended",
    "LicenseExpired",
    "LicenseCancelled",
    "LicenseUpgraded",
    "LicenseDowngraded",
    "UsageLimitExceeded",
]

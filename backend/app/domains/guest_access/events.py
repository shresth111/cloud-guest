"""Lightweight, in-process domain events for the Guest Access Control
module.

Plain, frozen dataclasses constructed and logged synchronously by
``service.py`` -- mirrors ``app.domains.voucher.events``/
``app.domains.otp.events``'s identical "simplest thing that could work"
posture: no event bus, no publish/subscribe registry, no async dispatch.
See the Architecture Design Document §12 for why this remains the default
for every Phase 1-3 module (``notification``, in Phase 4, is the one
deliberate exception).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AccessRuleCreated:
    rule_id: uuid.UUID
    organization_id: uuid.UUID
    rule_type: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AccessRuleDeactivated:
    rule_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class AccessRuleDeleted:
    rule_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class GuestAccessDenied:
    """A resolved ``BLOCKLIST`` decision actually blocked a login attempt
    -- distinct from ``AccessRuleCreated``/etc. (rule CRUD), this is a
    decision-time event, only ever raised from
    ``AccessDecisionResolver``-driven enforcement."""

    identifier: str | None
    mac_address: str | None
    matched_rule_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "AccessRuleCreated",
    "AccessRuleDeactivated",
    "AccessRuleDeleted",
    "GuestAccessDenied",
]

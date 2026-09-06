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
class AccessRulesImported:
    """One bulk import of guest (identifier-keyed) rules finished.

    Carries counts rather than a rule id because a bulk import has no
    single subject -- and because the three counts are the only thing an
    operator actually asks about afterwards ("did my 200-row list land?").
    ``rejected_count`` is logged even when zero: a run that rejected
    nothing is a meaningfully different fact from one nobody recorded.
    """

    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    imported_count: int
    updated_count: int
    rejected_count: int
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


@dataclass(frozen=True, slots=True)
class WhitelistOnlyAccessDenied:
    """A property running in whitelist-only mode refused someone who
    matched no rule at all.

    Separate from ``GuestAccessDenied`` because it has no
    ``matched_rule_id`` to carry -- there was no rule; that is the entire
    reason for the refusal. Carries ``organization_id``/``location_id``
    instead, because the question an operator asks about this event is
    "which of my properties is turning people away, and how many?", not
    "which rule fired".
    """

    identifier: str | None
    mac_address: str | None
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "AccessRuleCreated",
    "AccessRulesImported",
    "AccessRuleDeactivated",
    "AccessRuleDeleted",
    "GuestAccessDenied",
    "WhitelistOnlyAccessDenied",
]

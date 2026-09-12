"""Lightweight, in-process domain events for the Content Filtering module.

Mirrors ``app.domains.firewall.events``'s own identical design exactly:
plain, frozen dataclasses constructed by ``ContentFilterService`` methods
and logged directly, synchronously -- no event bus, no publish/subscribe
registry, no async dispatch. Not part of the public API surface -- nothing
outside this module's own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ContentFilterRuleCreated:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ContentFilterRuleUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ContentFilterRuleDeleted:
    id: uuid.UUID
    router_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ContentFilterRulePushed:
    """A blocked site was realized on a real device.

    Unlike the three events above, this one records something that happened
    *outside* this database -- so it is the only one whose absence is
    detectable by looking at a router. It is also the only one that means
    the site is actually blocked; ``ContentFilterRuleCreated`` says nothing
    about any device, and for most of this domain's life that was all a
    "created" rule was.
    """

    id: uuid.UUID
    router_id: uuid.UUID
    value_type: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "ContentFilterRuleCreated",
    "ContentFilterRuleUpdated",
    "ContentFilterRuleDeleted",
    "ContentFilterRulePushed",
]

"""Lightweight, in-process domain events for the Campaigns module.

Mirrors ``app.domains.qos.events``'s own identical design exactly: plain,
frozen dataclasses constructed by ``CampaignService`` methods and logged
directly, synchronously -- no event bus, no publish/subscribe registry,
no async dispatch. Not part of the public API surface -- nothing outside
this module's own ``service.py`` constructs or reads these.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class CampaignCreated:
    id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CampaignUpdated:
    id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CampaignStatusChanged:
    id: uuid.UUID
    from_status: str
    to_status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CampaignDeleted:
    id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CampaignResponseSubmitted:
    id: uuid.UUID
    campaign_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CampaignImpressionRecorded:
    id: uuid.UUID
    campaign_id: uuid.UUID
    was_skipped: bool
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "CampaignCreated",
    "CampaignUpdated",
    "CampaignStatusChanged",
    "CampaignDeleted",
    "CampaignResponseSubmitted",
    "CampaignImpressionRecorded",
]

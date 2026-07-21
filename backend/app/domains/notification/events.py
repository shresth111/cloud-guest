"""Frozen dataclass events for the notification domain -- constructed and
logged synchronously by ``service.py``, no event bus. Mirrors the existing
pattern every other domain in this codebase already uses (see ADD §12)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class NotificationEnqueued:
    delivery_id: uuid.UUID
    event_type: str
    channel: str


@dataclass(frozen=True)
class NotificationDelivered:
    delivery_id: uuid.UUID
    event_type: str
    channel: str
    attempt_count: int


@dataclass(frozen=True)
class NotificationDeliveryFailed:
    delivery_id: uuid.UUID
    event_type: str
    channel: str
    attempt_count: int
    error_message: str
    is_terminal: bool

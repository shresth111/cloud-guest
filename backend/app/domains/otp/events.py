"""Lightweight, in-process domain events for the OTP module.

Plain, frozen dataclasses constructed by ``OtpService`` methods and logged
synchronously by that same service -- mirrors
``app.domains.wireguard.events``/``app.domains.router_agent.events``'s
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
class OtpRequested:
    otp_request_id: uuid.UUID
    identifier: str
    channel: str
    purpose: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class OtpVerified:
    otp_request_id: uuid.UUID
    identifier: str
    purpose: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class OtpVerificationFailed:
    otp_request_id: uuid.UUID | None
    identifier: str
    purpose: str
    reason: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = ["OtpRequested", "OtpVerified", "OtpVerificationFailed"]

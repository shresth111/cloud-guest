"""Extension points other lanes plug into the PPPoE authorize decision.

JAZE-2 (FUP / night boost / MAC binding / concurrency) registers here instead
of editing ``pppoe_service``. Both registries are evaluated in registration
order inside ``IspPppoeService.authorize``. A hook that raises is logged and
**ignored** (fail-open for rate hooks, fail-open for gates): a bug in an
optional policy must not lock every subscriber out. A gate that wants to
fail closed returns ``PppoeGateResult(allow=False, ...)`` explicitly.

Contract (posted in LANE_NOTES as [JAZE-6]):

    async def gate(ctx: PppoeAuthorizeContext) -> PppoeGateResult | None
        None = no opinion. allow=False -> Access-Reject with ``reason``.
        ``reply`` may add/override RADIUS reply attributes on accept.

    async def rate(ctx: PppoeAuthorizeContext, base: SpeedGroupRate | None)
            -> SpeedGroupRate | None
        Return the effective rate (e.g. the FUP fallback or the night-boost
        group), or ``base`` unchanged. None = unlimited.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

__all__ = [
    "PppoeAuthorizeContext",
    "PppoeGateResult",
    "SpeedGroupRate",
    "clear_pppoe_hooks",
    "pppoe_gates",
    "pppoe_rate_resolvers",
    "register_pppoe_gate",
    "register_pppoe_rate_resolver",
]


@dataclass(frozen=True)
class SpeedGroupRate:
    download_kbps: int
    upload_kbps: int
    burst_download_kbps: int | None = None
    burst_upload_kbps: int | None = None
    burst_threshold_kbps: int | None = None
    burst_time_seconds: int | None = None
    priority: int = 8
    speed_group_id: uuid.UUID | None = None


@dataclass(frozen=True)
class PppoeAuthorizeContext:
    session: Any  # AsyncSession
    now: datetime
    isp_organization_id: uuid.UUID
    customer_organization_id: uuid.UUID
    location_id: uuid.UUID | None
    router_id: uuid.UUID | None
    nas_client_id: uuid.UUID
    subscriber: Any  # IspSubscriber
    credential: Any  # IspPppoeCredential
    calling_station_id: str | None
    nas_port_id: str | None


@dataclass
class PppoeGateResult:
    allow: bool = True
    reason: str | None = None
    reply: dict[str, Any] = field(default_factory=dict)


GateFn = Callable[[PppoeAuthorizeContext], Awaitable[PppoeGateResult | None]]
RateFn = Callable[
    [PppoeAuthorizeContext, SpeedGroupRate | None], Awaitable[SpeedGroupRate | None]
]

_gates: list[GateFn] = []
_rates: list[RateFn] = []


def register_pppoe_gate(fn: GateFn) -> GateFn:
    if fn not in _gates:
        _gates.append(fn)
    return fn


def register_pppoe_rate_resolver(fn: RateFn) -> RateFn:
    if fn not in _rates:
        _rates.append(fn)
    return fn


def pppoe_gates() -> list[GateFn]:
    return list(_gates)


def pppoe_rate_resolvers() -> list[RateFn]:
    return list(_rates)


def clear_pppoe_hooks() -> None:
    """Tests only."""
    _gates.clear()
    _rates.clear()

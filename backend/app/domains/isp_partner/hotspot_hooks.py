"""ENFORCE-2: extension point the hotspot RADIUS Authorize calls for ISP-partner
package rules.

Founder-approved exception (LANE_NOTES [COORD] 2026-11-01): the old hotspot
authorize (``guest.service.RadiusService.authorize``) makes ONE call here,
``run_hotspot_gates``, and wraps its accept result in
``apply_hotspot_verdict``. Both are an identity for everyone else:

- ``run_hotspot_gates`` returns ``None`` -- before any query -- while
  ``ISP_PARTNER_ENABLED`` / ``ISP_PARTNER_ENFORCEMENT_ENABLED`` are off or no
  gate is registered; ``None`` for an organization that is not an ISP
  customer (one cached lookup, the X1 cache); and each gate returns ``None``
  for a guest who is not an ISP subscriber.
- ``apply_hotspot_verdict(None, result)`` returns ``result`` itself (same
  object), so the reply is byte-identical.

Contract:

    async def gate(ctx: HotspotAuthorizeContext) -> HotspotGateResult | None
        None = no opinion. allow=False -> Access-Reject (the same reject the
        old authorize already sends). On accept, ``session_timeout_cap`` /
        ``idle_timeout_cap`` may only SHORTEN the old values.

A gate that raises is logged and ignored (fail-open), inside a SAVEPOINT so a
failed query cannot poison the request's transaction. First refusal wins;
caps combine with min().
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .config import get_isp_partner_settings

logger = logging.getLogger(__name__)

__all__ = [
    "HotspotAuthorizeContext",
    "HotspotGateResult",
    "apply_hotspot_verdict",
    "clear_hotspot_gates",
    "hotspot_gates",
    "register_hotspot_gate",
    "run_hotspot_gates",
]


@dataclass(frozen=True)
class HotspotAuthorizeContext:
    db: Any  # AsyncSession
    now: datetime
    guest_session: Any  # GuestSession (ACTIVE, about to be accepted)
    router: Any  # Router bound to the NAS
    calling_station_id: str | None


@dataclass(frozen=True)
class HotspotGateResult:
    allow: bool = True
    reason: str | None = None
    session_timeout_cap: int | None = None
    idle_timeout_cap: int | None = None


GateFn = Callable[[HotspotAuthorizeContext], Awaitable[HotspotGateResult | None]]

_gates: list[GateFn] = []


def register_hotspot_gate(fn: GateFn) -> GateFn:
    if fn not in _gates:
        _gates.append(fn)
    return fn


def hotspot_gates() -> tuple[GateFn, ...]:
    return tuple(_gates)


def clear_hotspot_gates() -> None:
    """Tests only."""
    _gates.clear()


def _on() -> bool:
    s = get_isp_partner_settings()
    return bool(s.enabled and s.enforcement_enabled)


def _min(a: int | None, b: int | None) -> int | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


async def _is_isp_org(db: Any, organization_id: Any) -> bool:
    """Is this an ISP customer's organization? Cached 60 s in the X1 cache;
    a miss is looked up inside a SAVEPOINT so it can never abort the
    request's transaction. Any error = not ours (fail-open)."""
    import time

    from .rate_limit import IspRateLimitLookup, _isp_customer_cache

    if organization_id is None:
        return False
    hit = _isp_customer_cache.get(organization_id)
    if hit is not None and hit[1] > time.monotonic():
        return hit[0]
    try:
        async with db.begin_nested():
            return await IspRateLimitLookup(None)._is_isp_customer(db, organization_id)
    except Exception:  # noqa: BLE001
        logger.warning("isp_hotspot_org_check_failed", exc_info=True)
        return False


async def run_hotspot_gates(
    *,
    db: Any,
    guest_session: Any,
    router: Any,
    calling_station_id: str | None,
    now: datetime | None = None,
) -> HotspotGateResult | None:
    """The one call the hotspot Authorize makes. None = no opinion."""
    if not _gates or not _on() or db is None or guest_session is None:
        return None
    if not await _is_isp_org(db, getattr(guest_session, "organization_id", None)):
        return None
    from datetime import UTC

    ctx = HotspotAuthorizeContext(
        db=db,
        now=now or datetime.now(UTC),
        guest_session=guest_session,
        router=router,
        calling_station_id=calling_station_id,
    )
    out: HotspotGateResult | None = None
    for gate in tuple(_gates):
        try:
            async with db.begin_nested():
                res = await gate(ctx)
        except Exception:  # noqa: BLE001 -- fail-open, see module docstring
            logger.warning("isp_hotspot_gate_failed", exc_info=True)
            continue
        if res is None:
            continue
        if not res.allow:
            return res
        out = HotspotGateResult(
            allow=True,
            session_timeout_cap=_min(
                out.session_timeout_cap if out else None, res.session_timeout_cap
            ),
            idle_timeout_cap=_min(
                out.idle_timeout_cap if out else None, res.idle_timeout_cap
            ),
        )
    return out


def apply_hotspot_verdict(verdict: HotspotGateResult | None, result: Any) -> Any:
    """Shorten the accept result's timeouts. Identity (same object) when there
    is nothing to apply, or for a reject."""
    if verdict is None or not getattr(result, "authorized", False):
        return result
    st = result.session_timeout_seconds
    it = result.idle_timeout_seconds
    new_st = _min(st, verdict.session_timeout_cap)
    new_it = _min(it, verdict.idle_timeout_cap)
    if new_st is not None:
        new_st = max(int(new_st), 1)  # 0 may read as "unlimited" on a NAS
    if new_it is not None:
        new_it = max(int(new_it), 1)
    if new_st == st and new_it == it:
        return result
    return dataclasses.replace(
        result, session_timeout_seconds=new_st, idle_timeout_seconds=new_it
    )

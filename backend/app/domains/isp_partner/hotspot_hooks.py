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

A gate that raises is logged and ignored (fail-open), inside a SAVEPOINT.
First refusal wins; caps combine with min().

ENFORCE-4: the gates run on their own DB session within a time budget
(``ISP_PARTNER_HOTSPOT_GATE_BUDGET_MS``, default 200 ms); past it the login
goes ahead (fail-open). See ``run_hotspot_gates``.
"""

from __future__ import annotations

import asyncio
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
    "register_hotspot_timeout_hook",
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


#: ENFORCE-4: where the gate gets its own DB session (tests swap it).
_session_factory: Any = None
#: {organization_id: monotonic time of the last timeout warning}
_timeout_logged: dict[Any, float] = {}


def _cached_isp_org(organization_id: Any) -> bool | None:
    """The X1 cache's answer, or None on a miss (no DB here)."""
    import time

    from .rate_limit import _isp_customer_cache

    hit = _isp_customer_cache.get(organization_id)
    if hit is not None and hit[1] > time.monotonic():
        return hit[0]
    return None


def _sessions() -> Any:
    if _session_factory is not None:
        return _session_factory
    from app.database.session import SessionLocal

    return SessionLocal


def _swallow(task: asyncio.Task) -> None:
    if not task.cancelled():
        task.exception()


async def run_hotspot_gates(
    *,
    db: Any,
    guest_session: Any,
    router: Any,
    calling_station_id: str | None,
    now: datetime | None = None,
) -> HotspotGateResult | None:
    """The one call the hotspot Authorize makes. None = no opinion.

    ENFORCE-4 (BE review F14): the gate runs on its OWN DB session, as a task
    the Authorize waits for at most ``hotspot_gate_budget_ms`` (default
    200 ms). Past that the login goes ahead (fail-open) and the task finishes
    in the background, bounded by the same ``statement_timeout``. It then
    rolls its writes back and records one ``gate_timeout`` event per
    subscriber per minute. The request's own session and connection are
    never touched, so a slow or cancelled gate cannot break the old
    Authorize. A regular tenant whose organization is cached as "not an ISP
    customer" (the X1 cache, 60 s) costs nothing: no task, no query.
    """
    if not _gates or not _on() or db is None or guest_session is None:
        return None
    org_id = getattr(guest_session, "organization_id", None)
    if org_id is None:
        return None
    cached = _cached_isp_org(org_id)
    if cached is False:
        return None
    from datetime import UTC

    budget_ms = int(get_isp_partner_settings().hotspot_gate_budget_ms)
    state = {"timed_out": False}
    task = asyncio.create_task(
        _evaluate(
            org_id=org_id,
            session_id=guest_session.id,
            router=router,
            calling_station_id=calling_station_id,
            now=now or datetime.now(UTC),
            check_org=cached is None,
            budget_ms=budget_ms,
            state=state,
        )
    )
    done, _pending = await asyncio.wait({task}, timeout=budget_ms / 1000)
    if not done:
        state["timed_out"] = True
        task.add_done_callback(_swallow)
        _log_timeout(org_id, budget_ms)
        return None
    try:
        return task.result()
    except Exception:  # noqa: BLE001 -- fail-open, see module docstring
        logger.warning("isp_hotspot_gate_failed", exc_info=True)
        return None


def _log_timeout(org_id: Any, budget_ms: int) -> None:
    import time

    now = time.monotonic()
    if now - _timeout_logged.get(org_id, 0.0) >= 60:
        _timeout_logged[org_id] = now
        logger.warning(
            "isp_hotspot_gate_timeout",
            extra={"event_org": str(org_id), "event_budget_ms": budget_ms},
        )


async def _evaluate(
    *,
    org_id: Any,
    session_id: Any,
    router: Any,
    calling_station_id: str | None,
    now: datetime,
    check_org: bool,
    budget_ms: int,
    state: dict,
) -> HotspotGateResult | None:
    from sqlalchemy import text

    from app.domains.guest.models import GuestSession

    async with _sessions()() as db:
        await db.execute(text(f"SET LOCAL statement_timeout = {int(budget_ms)}"))
        if check_org:
            from .rate_limit import IspRateLimitLookup

            if not await IspRateLimitLookup(None)._is_isp_customer(db, org_id):
                return None
        gs = await db.get(GuestSession, session_id)
        if gs is None:
            return None
        ctx = HotspotAuthorizeContext(
            db=db,
            now=now,
            guest_session=gs,
            router=router,
            calling_station_id=calling_station_id,
        )
        out: HotspotGateResult | None = None
        for gate in tuple(_gates):
            try:
                async with db.begin_nested():
                    res = await gate(ctx)
            except Exception:  # noqa: BLE001 -- fail-open
                logger.warning("isp_hotspot_gate_failed", exc_info=True)
                continue
            if res is None:
                continue
            if not res.allow:
                out = res
                break
            out = HotspotGateResult(
                allow=True,
                session_timeout_cap=_min(
                    out.session_timeout_cap if out else None, res.session_timeout_cap
                ),
                idle_timeout_cap=_min(
                    out.idle_timeout_cap if out else None, res.idle_timeout_cap
                ),
            )
        if state["timed_out"]:
            # The login already went ahead without this verdict: keep none of
            # its writes (a refusal event would be a lie), say why instead.
            await db.rollback()
            gs = await db.get(GuestSession, session_id)  # rollback expired it
            for hook in tuple(_timeout_hooks):
                try:
                    await hook(db, gs, now, budget_ms)
                except Exception:  # noqa: BLE001
                    logger.warning("isp_hotspot_timeout_hook_failed", exc_info=True)
            await db.commit()
            return None
        await db.commit()
        return out


TimeoutHook = Callable[[Any, Any, datetime, int], Awaitable[None]]
_timeout_hooks: list[TimeoutHook] = []


def register_hotspot_timeout_hook(fn: TimeoutHook) -> TimeoutHook:
    if fn not in _timeout_hooks:
        _timeout_hooks.append(fn)
    return fn


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

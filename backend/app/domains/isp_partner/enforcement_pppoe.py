"""ENFORCE-1: JAZE-2 package rules on the PPPoE Authorize path.

Registered into JAZE-6's ``pppoe_hooks`` (no edit to ``pppoe_service``). Only
ISP-partner PPPoE subscribers ever reach these hooks: the PPPoE authorize
refuses any NAS that is not an ISP customer's before the hooks run. Both
hooks are a no-op unless ``ISP_PARTNER_ENFORCEMENT_ENABLED`` is on and the
subscriber's package has a JAZE-2 policy.

Gate, in order (first refusal wins):
1. MAC: auto-bind the first ``mac_bind_count`` devices; with binding or
   ``mac_restriction`` on, a device that is not bound is refused
   (``mac_not_bound``).
2. IP restriction: the subscriber must hold a JAZE-2 static IP; the reply
   pins it with ``Framed-IP-Address`` (``no_static_ip`` otherwise).
3. Concurrency: refused while live sessions (PPPoE + hotspot) from OTHER
   devices are already >= ``max_simultaneous`` (``concurrency``). A device
   reconnecting replaces its own stale session, so it is not counted.
4. Timeouts: ``Session-Timeout`` = min(hard timeout, JAZE-6's own value)
   and ``Idle-Timeout`` from the policy.
Every refusal and auto-bind is a JAZE-2 enforcement event.

Rate: FUP fallback when throttled, else the boost group inside the boost
window, plus the package queue priority -- the same precedence as the X1
hotspot path (``enforcement.effective_rate_override``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from .config import get_isp_partner_settings
from .pppoe_hooks import (
    PppoeAuthorizeContext,
    PppoeGateResult,
    SpeedGroupRate,
    register_pppoe_gate,
    register_pppoe_rate_resolver,
)

#: refusal reasons (<= 32 chars: pppoe_service truncates there)
R_MAC = "mac_not_bound"
R_IP = "no_static_ip"
R_CONCURRENCY = "concurrency"


def _on() -> bool:
    s = get_isp_partner_settings()
    return bool(s.enabled and s.enforcement_enabled)


async def _policy(ctx: PppoeAuthorizeContext) -> Any:
    from .enforcement import _policy_for_package

    sub = ctx.subscriber
    if sub is None or sub.package_id is None:
        return None
    return await _policy_for_package(ctx.session, sub.package_id)


async def _bound_macs(session: Any, subscriber_id: uuid.UUID) -> list[str]:
    from .enforcement_models import IspSubscriberMacBinding as M

    return list(
        (
            await session.execute(
                select(M.mac)
                .where(M.subscriber_id == subscriber_id, M.is_deleted.is_(False))
                .order_by(M.created_at)
            )
        ).scalars()
    )


async def _static_ip(session: Any, subscriber_id: uuid.UUID) -> str | None:
    from .enforcement_models import IspSubscriberIpBinding as B

    return (
        await session.execute(
            select(B.ip)
            .where(B.subscriber_id == subscriber_id, B.is_deleted.is_(False))
            .order_by(B.created_at)
            .limit(1)
        )
    ).scalar_one_or_none()


async def _live_other_devices(ctx: PppoeAuthorizeContext) -> int:
    """Live PPPoE sessions of this subscriber from other devices, plus its
    live hotspot sessions."""
    from app.domains.guest.constants import GuestSessionStatus
    from app.domains.guest.models import GuestSession

    from .pppoe_models import IspPppoeSession as P

    q = select(func.count()).where(
        P.subscriber_id == ctx.subscriber.id,
        P.status == "active",
        P.is_deleted.is_(False),
    )
    if ctx.calling_station_id:
        q = q.where(
            (P.calling_station_id.is_(None))
            | (func.upper(P.calling_station_id) != ctx.calling_station_id.upper())
        )
    n = int((await ctx.session.execute(q)).scalar_one())
    gid = getattr(ctx.subscriber, "guest_id", None)
    if gid is not None:
        n += int(
            (
                await ctx.session.execute(
                    select(func.count()).where(
                        GuestSession.guest_id == gid,
                        GuestSession.organization_id
                        == ctx.subscriber.customer_organization_id,
                        GuestSession.status == GuestSessionStatus.ACTIVE.value,
                    )
                )
            ).scalar_one()
        )
    return n


async def _event(ctx: PppoeAuthorizeContext, kind: str, detail: str) -> None:
    from .enforcement import record_event

    await record_event(
        ctx.session,
        isp_id=ctx.isp_organization_id,
        subscriber_id=ctx.subscriber.id,
        kind=kind,
        detail=f"pppoe: {detail}",
        now=ctx.now,
    )


def timeout_reply(
    policy: Any, *, now: datetime, valid_until: datetime | None, max_session_s: int
) -> dict[str, int]:
    """Session-/Idle-Timeout reply attributes. The hard timeout only ever
    shortens JAZE-6's own Session-Timeout (validity, configured maximum)."""
    out: dict[str, int] = {}
    if policy.hard_timeout_s:
        base = int(max_session_s)
        if valid_until is not None:
            base = min(base, max(60, int((valid_until - now).total_seconds())))
        out["reply:Session-Timeout"] = min(base, int(policy.hard_timeout_s))
    if policy.idle_timeout_s:
        out["reply:Idle-Timeout"] = int(policy.idle_timeout_s)
    return out


async def jaze2_pppoe_gate(ctx: PppoeAuthorizeContext) -> PppoeGateResult | None:
    if not _on():
        return None
    policy = await _policy(ctx)
    if policy is None:
        return None
    from .enforcement import norm_mac
    from .enforcement_models import IspSubscriberMacBinding
    from .pppoe_config import get_isp_pppoe_settings

    mac = norm_mac(ctx.calling_station_id)
    bind_n = int(policy.mac_bind_count or 0)
    restrict = bool(policy.mac_restriction) or bind_n > 0
    if restrict:
        bound = {m.upper() for m in await _bound_macs(ctx.session, ctx.subscriber.id)}
        if mac and mac not in bound and bind_n > 0 and len(bound) < bind_n:
            ctx.session.add(
                IspSubscriberMacBinding(
                    isp_organization_id=ctx.isp_organization_id,
                    subscriber_id=ctx.subscriber.id,
                    mac=mac,
                    source="auto",
                )
            )
            await _event(ctx, "mac_bound", mac)
            bound.add(mac)
        if bound and (not mac or mac not in bound):
            await _event(ctx, "mac_reject", mac or "no MAC")
            return PppoeGateResult(allow=False, reason=R_MAC)
    reply: dict[str, Any] = {}
    if policy.ip_restriction:
        ip = await _static_ip(ctx.session, ctx.subscriber.id)
        if ip is None:
            await _event(ctx, "ip_reject", "no static IP bound")
            return PppoeGateResult(allow=False, reason=R_IP)
        reply["reply:Framed-IP-Address"] = ip
    if policy.max_simultaneous:
        live = await _live_other_devices(ctx)
        if live >= int(policy.max_simultaneous):
            await _event(
                ctx, "concurrency", f"{live} live, limit {policy.max_simultaneous}"
            )
            return PppoeGateResult(allow=False, reason=R_CONCURRENCY)
    reply.update(
        timeout_reply(
            policy,
            now=ctx.now,
            valid_until=ctx.subscriber.valid_until,
            max_session_s=get_isp_pppoe_settings().max_session_timeout_seconds,
        )
    )
    return PppoeGateResult(allow=True, reply=reply)


async def jaze2_pppoe_rate(
    ctx: PppoeAuthorizeContext, base: SpeedGroupRate | None
) -> SpeedGroupRate | None:
    if not _on():
        return base
    policy = await _policy(ctx)
    if policy is None:
        return base
    from .enforcement import _org_tz, boost_active
    from .enforcement_models import IspSubscriberUsage
    from .plans_models import IspSpeedGroup

    group_id = None
    if policy.fup_fallback_speed_group_id:
        usage = (
            await ctx.session.execute(
                select(IspSubscriberUsage).where(
                    IspSubscriberUsage.subscriber_id == ctx.subscriber.id,
                    IspSubscriberUsage.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        if usage is not None and usage.throttled:
            group_id = policy.fup_fallback_speed_group_id
    if (
        group_id is None
        and policy.boost_speed_group_id
        and boost_active(
            policy.boost_start_minute,
            policy.boost_end_minute,
            ctx.now,
            await _org_tz(ctx.session, policy.isp_organization_id),
        )
    ):
        group_id = policy.boost_speed_group_id
    if group_id is not None:
        g = await ctx.session.get(IspSpeedGroup, group_id)
        if g is None or g.is_deleted or not (g.download_kbps or g.upload_kbps):
            return base
        from .pppoe_service import _rate_from_group

        rate = _rate_from_group(g)
    elif base is not None:
        rate = base
    else:
        return base
    if policy.queue_priority:
        # Mikrotik-Rate-Limit carries the priority only after the burst
        # fields; without a burst, zero bursts ("no burst") reach it -- the
        # same encoding JAZE-2's hotspot ``rate_from_group`` uses.
        no_burst = rate.burst_download_kbps is None and rate.burst_upload_kbps is None
        rate = SpeedGroupRate(
            download_kbps=rate.download_kbps,
            upload_kbps=rate.upload_kbps,
            burst_download_kbps=0 if no_burst else rate.burst_download_kbps,
            burst_upload_kbps=0 if no_burst else rate.burst_upload_kbps,
            burst_threshold_kbps=0 if no_burst else rate.burst_threshold_kbps,
            burst_time_seconds=0 if no_burst else rate.burst_time_seconds,
            priority=int(policy.queue_priority),
            speed_group_id=rate.speed_group_id,
        )
    return rate


register_pppoe_gate(jaze2_pppoe_gate)
register_pppoe_rate_resolver(jaze2_pppoe_rate)

__all__ = [
    "R_CONCURRENCY",
    "R_IP",
    "R_MAC",
    "jaze2_pppoe_gate",
    "jaze2_pppoe_rate",
    "timeout_reply",
]

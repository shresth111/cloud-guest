"""ENFORCE-2: JAZE-2 package rules at the hotspot RADIUS Authorize.

Registered into ``hotspot_hooks`` (the one call the old hotspot authorize
makes). A no-op (``None``) unless ``ISP_PARTNER_ENFORCEMENT_ENABLED`` is on,
the session's organization is an ISP customer, the guest is an enabled ISP
subscriber, and that subscriber's package has a JAZE-2 policy. The JAZE-2
minute sweep stays the fallback for everything that changes after login.

Same rules and order as the sweep (``enforcement.access_verdicts``) and the
PPPoE gate (``enforcement_pppoe``), first refusal wins:
1. hard timeout already spent -> refuse (``hard_timeout``);
2. MAC: auto-bind the first ``mac_bind_count`` devices; with binding or
   ``mac_restriction`` on, an unbound device is refused (``mac_not_bound``);
3. IP restriction: no static IP bound -> refuse (``no_static_ip``); the
   session's IP known and not a bound one -> refuse (``ip_not_allowed``);
4. concurrency: live hotspot sessions of the subscriber from OTHER devices
   plus its live PPPoE sessions >= ``max_simultaneous`` -> refuse
   (``concurrency``).
On accept: Session-Timeout capped at what is left of the hard timeout and
Idle-Timeout capped at the policy's (both only ever shorten).
Refusals and auto-binds are enforcement events (detail "hotspot: ...");
the same refusal (kind + detail) is recorded at most once a minute, since a
NAS retries.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select

from .hotspot_hooks import (
    HotspotAuthorizeContext,
    HotspotGateResult,
    register_hotspot_gate,
)

R_HARD = "hard_timeout"
R_MAC = "mac_not_bound"
R_NO_IP = "no_static_ip"
R_IP = "ip_not_allowed"
R_CONCURRENCY = "concurrency"

_EVENT_DEDUPE = timedelta(seconds=60)


async def _subscriber(db: Any, gs: Any) -> Any:
    from app.domains.voucher.models import Voucher

    from .plans_models import IspSubscriber as S

    sub = None
    if gs.guest_id is not None:
        sub = (
            (
                await db.execute(
                    select(S)
                    .where(
                        S.customer_organization_id == gs.organization_id,
                        S.guest_id == gs.guest_id,
                        S.is_deleted.is_(False),
                    )
                    .order_by(S.created_at)
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
    if sub is None and getattr(gs, "voucher_id", None) is not None:
        ident = (
            await db.execute(
                select(Voucher.redeemed_identifier).where(Voucher.id == gs.voucher_id)
            )
        ).scalar_one_or_none()
        if ident:
            sub = (
                await db.execute(
                    select(S).where(
                        S.customer_organization_id == gs.organization_id,
                        S.identifier == ident,
                        S.is_deleted.is_(False),
                    )
                )
            ).scalar_one_or_none()
            # A subscriber the ISP created by hand is never linked to its
            # guest (sync_subscribers links only the ones it creates), so the
            # JAZE-2 sweep and FUP usage, which read sessions by guest_id,
            # never saw its hotspot sessions (found on the CHR, ENFORCE-2).
            # Link it here, once, to the guest that just logged in with its
            # identifier in this same customer org.
            if sub is not None and sub.guest_id is None and gs.guest_id is not None:
                sub.guest_id = gs.guest_id
    return sub


async def _event(
    ctx: HotspotAuthorizeContext, sub: Any, kind: str, detail: str, *, dedupe: bool
) -> None:
    from .enforcement import record_event
    from .enforcement_models import IspEnforcementEvent as E

    if dedupe:
        recent = (
            await ctx.db.execute(
                select(E.id)
                .where(
                    E.subscriber_id == sub.id,
                    E.kind == kind,
                    E.detail == f"hotspot: {detail}"[:255],
                    E.occurred_at > ctx.now - _EVENT_DEDUPE,
                )
                .limit(1)
            )
        ).first()
        if recent is not None:
            return
    await record_event(
        ctx.db,
        isp_id=sub.isp_organization_id,
        subscriber_id=sub.id,
        kind=kind,
        detail=f"hotspot: {detail}",
        session_id=ctx.guest_session.id,
        now=ctx.now,
    )


async def _session_mac(db: Any, gs: Any) -> str | None:
    from app.domains.guest.models import GuestDevice

    if gs.device_id is None:
        return None
    return (
        await db.execute(
            select(GuestDevice.mac_address).where(GuestDevice.id == gs.device_id)
        )
    ).scalar_one_or_none()


async def _live_others(ctx: HotspotAuthorizeContext, sub: Any, mac: str | None) -> int:
    from app.domains.guest.constants import GuestSessionStatus
    from app.domains.guest.models import GuestDevice, GuestSession

    from .enforcement import norm_mac
    from .pppoe_models import IspPppoeSession as P

    gs = ctx.guest_session
    rows = (
        await ctx.db.execute(
            select(GuestSession.id, GuestDevice.mac_address)
            .outerjoin(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .where(
                GuestSession.guest_id == gs.guest_id,
                GuestSession.organization_id == gs.organization_id,
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
                GuestSession.id != gs.id,
            )
        )
    ).all()
    n = sum(1 for _sid, m in rows if not (mac and norm_mac(m) == mac))
    n += int(
        (
            await ctx.db.execute(
                select(func.count()).where(
                    P.subscriber_id == sub.id,
                    P.status == "active",
                    P.is_deleted.is_(False),
                )
            )
        ).scalar_one()
    )
    return n


async def jaze2_hotspot_gate(ctx: HotspotAuthorizeContext) -> HotspotGateResult | None:
    from .enforcement import _policy_for_package, norm_mac
    from .enforcement_models import IspSubscriberIpBinding, IspSubscriberMacBinding

    gs = ctx.guest_session
    # run_hotspot_gates already checked the org is an ISP customer's.
    sub = await _subscriber(ctx.db, gs)
    if sub is None or sub.status == "disabled" or sub.package_id is None:
        return None
    policy = await _policy_for_package(ctx.db, sub.package_id)
    if policy is None:
        return None

    def refuse(reason: str) -> HotspotGateResult:
        return HotspotGateResult(allow=False, reason=reason)

    # 1. hard timeout
    cap: int | None = None
    if policy.hard_timeout_s:
        started = gs.started_at
        elapsed = (ctx.now - started).total_seconds() if started else 0
        left = int(policy.hard_timeout_s) - int(elapsed)
        if left <= 0:
            await _event(
                ctx, sub, "hard_timeout", f"{policy.hard_timeout_s}s", dedupe=True
            )
            return refuse(R_HARD)
        cap = left

    # 2. MAC
    mac = norm_mac(ctx.calling_station_id) or norm_mac(await _session_mac(ctx.db, gs))
    bind_n = int(policy.mac_bind_count or 0)
    if bool(policy.mac_restriction) or bind_n > 0:
        bound = {
            norm_mac(m)
            for m in (
                await ctx.db.execute(
                    select(IspSubscriberMacBinding.mac).where(
                        IspSubscriberMacBinding.subscriber_id == sub.id,
                        IspSubscriberMacBinding.is_deleted.is_(False),
                    )
                )
            ).scalars()
            if m
        }
        if mac and mac not in bound and bind_n > 0 and len(bound) < bind_n:
            ctx.db.add(
                IspSubscriberMacBinding(
                    isp_organization_id=sub.isp_organization_id,
                    subscriber_id=sub.id,
                    mac=mac,
                    source="auto",
                )
            )
            await _event(ctx, sub, "mac_bound", mac, dedupe=False)
            bound.add(mac)
        if bound and (not mac or mac not in bound):
            await _event(ctx, sub, "mac_reject", mac or "no MAC", dedupe=True)
            return refuse(R_MAC)

    # 3. IP restriction
    if policy.ip_restriction:
        ips = set(
            (
                await ctx.db.execute(
                    select(IspSubscriberIpBinding.ip).where(
                        IspSubscriberIpBinding.subscriber_id == sub.id,
                        IspSubscriberIpBinding.is_deleted.is_(False),
                    )
                )
            ).scalars()
        )
        if not ips:
            await _event(ctx, sub, "ip_reject", "no static IP bound", dedupe=True)
            return refuse(R_NO_IP)
        ip = getattr(gs, "ip_address", None)
        if ip and str(ip) not in ips:
            await _event(ctx, sub, "ip_reject", str(ip), dedupe=True)
            return refuse(R_IP)

    # 4. concurrency
    if policy.max_simultaneous:
        live = await _live_others(ctx, sub, mac)
        if live >= int(policy.max_simultaneous):
            await _event(
                ctx,
                sub,
                "concurrency",
                f"{live} live, limit {policy.max_simultaneous}",
                dedupe=True,
            )
            return refuse(R_CONCURRENCY)

    return HotspotGateResult(
        allow=True,
        session_timeout_cap=cap,
        idle_timeout_cap=int(policy.idle_timeout_s) if policy.idle_timeout_s else None,
    )


register_hotspot_gate(jaze2_hotspot_gate)

__all__ = [
    "R_CONCURRENCY",
    "R_HARD",
    "R_IP",
    "R_MAC",
    "R_NO_IP",
    "jaze2_hotspot_gate",
]

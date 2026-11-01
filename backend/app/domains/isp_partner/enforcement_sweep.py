"""The JAZE-2 minute sweep (Celery beat ``isp-enforcement-sweep``, E7).

For every package with a policy row it, per active subscriber (one
SAVEPOINT each, so one failure never blocks the rest):

1. starts validity at first login when the package says so;
2. recomputes FUP usage and flips the throttle flag;
3. checks the subscriber's live sessions against MAC/IP/concurrency/timeout
   rules and ends the offenders;
4. on a throttle flip or a boost-window edge, ends live sessions so the
   router re-authorizes them -- only when the live mode is ``reauth``.

Ending a session goes through the injected ``disconnect`` callable, which
in production is the existing ``GuestService.disconnect_session``.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from .config import get_isp_partner_settings
from .enforcement import (
    SessionFacts,
    _org_tz,
    access_verdicts,
    boost_active,
    compute_usage,
    norm_mac,
    record_event,
)

logger = logging.getLogger(__name__)

Disconnect = Callable[[uuid.UUID, uuid.UUID, str], Awaitable[Any]]


async def _live_sessions(session: Any, sub: Any) -> list[SessionFacts]:
    from app.domains.guest.constants import GuestSessionStatus
    from app.domains.guest.models import GuestDevice, GuestSession

    if sub.guest_id is None:
        return []
    rows = (
        await session.execute(
            select(GuestSession, GuestDevice.mac_address)
            .outerjoin(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .where(
                GuestSession.guest_id == sub.guest_id,
                GuestSession.organization_id == sub.customer_organization_id,
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
            )
        )
    ).all()
    return [
        SessionFacts(
            session_id=gs.id,
            started_at=gs.started_at,
            last_activity_at=gs.last_activity_at,
            mac=mac,
            ip=gs.ip_address,
        )
        for gs, mac in rows
    ]


async def _bindings(session: Any, sub_id: uuid.UUID) -> tuple[set[str], set[str]]:
    from .enforcement_models import IspSubscriberIpBinding, IspSubscriberMacBinding

    macs = (
        await session.execute(
            select(IspSubscriberMacBinding.mac).where(
                IspSubscriberMacBinding.subscriber_id == sub_id,
                IspSubscriberMacBinding.is_deleted.is_(False),
            )
        )
    ).scalars()
    ips = (
        await session.execute(
            select(IspSubscriberIpBinding.ip).where(
                IspSubscriberIpBinding.subscriber_id == sub_id,
                IspSubscriberIpBinding.is_deleted.is_(False),
            )
        )
    ).scalars()
    return {norm_mac(m) for m in macs if m}, set(ips)


async def _first_login_validity(
    session: Any, sub: Any, package: Any, now: datetime
) -> bool:
    from app.domains.guest.models import GuestSession

    if sub.valid_until is not None or sub.guest_id is None or not package.validity_days:
        return False
    first = (
        await session.execute(
            select(GuestSession.started_at)
            .where(
                GuestSession.guest_id == sub.guest_id,
                GuestSession.organization_id == sub.customer_organization_id,
            )
            .order_by(GuestSession.started_at)
            .limit(1)
        )
    ).scalar_one_or_none()
    if first is None:
        return False
    sub.valid_until = first + timedelta(days=int(package.validity_days))
    await record_event(
        session,
        isp_id=sub.isp_organization_id,
        subscriber_id=sub.id,
        kind="validity_start",
        detail=f"first login {first.isoformat()}",
        now=now,
    )
    return True


async def run_sweep(
    session: Any,
    *,
    disconnect: Disconnect,
    now: datetime | None = None,
    live_mode: str | None = None,
) -> dict[str, int]:
    from .enforcement_models import IspPackagePolicy, IspSubscriberMacBinding
    from .plans_models import IspPackage, IspSubscriber

    settings = get_isp_partner_settings()
    summary = {
        "policies": 0,
        "subscribers": 0,
        "throttled": 0,
        "restored": 0,
        "ended": 0,
        "bound": 0,
        "errors": 0,
    }
    if not (settings.enabled and settings.enforcement_enabled):
        return summary
    now = now or datetime.now(UTC)
    live_mode = live_mode or settings.enforcement_live_mode
    policies = (
        (
            await session.execute(
                select(IspPackagePolicy).where(IspPackagePolicy.is_deleted.is_(False))
            )
        )
        .scalars()
        .all()
    )
    for policy in policies:
        summary["policies"] += 1
        package = await session.get(IspPackage, policy.package_id)
        if package is None:
            continue
        edge = False
        if policy.boost_speed_group_id:
            active = boost_active(
                policy.boost_start_minute,
                policy.boost_end_minute,
                now,
                await _org_tz(session, policy.isp_organization_id),
            )
            if active != bool(policy.boost_state_active):
                policy.boost_state_active = active
                edge = True
        subs = (
            (
                await session.execute(
                    select(IspSubscriber).where(
                        IspSubscriber.package_id == policy.package_id,
                        IspSubscriber.isp_organization_id == policy.isp_organization_id,
                        IspSubscriber.status == "active",
                        IspSubscriber.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        for sub in subs:
            summary["subscribers"] += 1
            try:
                async with session.begin_nested():
                    await _sweep_one(
                        session,
                        sub=sub,
                        policy=policy,
                        package=package,
                        edge=edge,
                        now=now,
                        live_mode=live_mode,
                        disconnect=disconnect,
                        summary=summary,
                        mac_model=IspSubscriberMacBinding,
                    )
            except Exception as exc:  # noqa: BLE001
                summary["errors"] += 1
                logger.warning(
                    "isp_enforcement_sweep_failed",
                    extra={"subscriber_id": str(sub.id), "error": str(exc)[:200]},
                )
    await session.flush()
    return summary


async def _sweep_one(
    session: Any,
    *,
    sub: Any,
    policy: Any,
    package: Any,
    edge: bool,
    now: datetime,
    live_mode: str,
    disconnect: Disconnect,
    summary: dict[str, int],
    mac_model: Any,
) -> None:
    if policy.validity_starts == "first_login":
        await _first_login_validity(session, sub, package, now)
    reauth = edge
    if policy.fup_limit_mb:
        _row, flipped = await compute_usage(
            session, subscriber=sub, policy=policy, package=package, now=now
        )
        if flipped is True:
            summary["throttled"] += 1
            reauth = True
            await record_event(
                session,
                isp_id=sub.isp_organization_id,
                subscriber_id=sub.id,
                kind="fup_throttle",
                detail="FUP limit reached",
                now=now,
            )
        elif flipped is False:
            summary["restored"] += 1
            reauth = True
            await record_event(
                session,
                isp_id=sub.isp_organization_id,
                subscriber_id=sub.id,
                kind="fup_restore",
                detail="full speed restored",
                now=now,
            )
    if edge:
        await record_event(
            session,
            isp_id=sub.isp_organization_id,
            subscriber_id=sub.id,
            kind="boost_on" if policy.boost_state_active else "boost_off",
            now=now,
        )
    live = await _live_sessions(session, sub)
    if not live:
        return
    macs, ips = await _bindings(session, sub.id)
    verdicts, to_bind = access_verdicts(policy, live, macs, ips, now=now)
    for mac in to_bind:
        session.add(
            mac_model(
                isp_organization_id=sub.isp_organization_id,
                subscriber_id=sub.id,
                mac=mac,
                source="auto",
            )
        )
        summary["bound"] += 1
        await record_event(
            session,
            isp_id=sub.isp_organization_id,
            subscriber_id=sub.id,
            kind="mac_bound",
            detail=mac,
            now=now,
        )
    ended: set[uuid.UUID] = set()
    for v in verdicts:
        await disconnect(v.session_id, sub.customer_organization_id, v.kind)
        ended.add(v.session_id)
        summary["ended"] += 1
        await record_event(
            session,
            isp_id=sub.isp_organization_id,
            subscriber_id=sub.id,
            kind=v.kind,
            detail=v.detail,
            session_id=v.session_id,
            now=now,
        )
    if reauth and live_mode == "reauth":
        for s in live:
            if s.session_id in ended:
                continue
            await disconnect(s.session_id, sub.customer_organization_id, "reauth")
            summary["ended"] += 1
            await record_event(
                session,
                isp_id=sub.isp_organization_id,
                subscriber_id=sub.id,
                kind="reauth",
                detail="speed change",
                session_id=s.session_id,
                now=now,
            )

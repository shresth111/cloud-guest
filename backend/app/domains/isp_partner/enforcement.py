"""JAZE-2 enforcement (ADDENDUM_05 J3): FUP, night boost, validity start,
MAC/IP binding, simultaneous logins, idle/hard timeouts.

Where each rule takes effect (no FreeRADIUS or old-code edit):

* **Speed** (FUP fallback, night boost, queue priority): the X1 wrapper
  (``rate_limit.IspRateLimitLookup``) asks :func:`effective_rate_override` on
  every Authorize of an ISP coupon session. A change for a session that is
  already online applies at its next authorize, or at once when
  ``ISP_PARTNER_ENFORCEMENT_LIVE_MODE=reauth`` (the sweep ends the live
  session through the existing ``GuestService.disconnect_session`` and the
  router re-authorizes it). CoA is not used: it has never worked here.
* **Access rules** (MAC bind/restriction, IP restriction, simultaneous
  logins, idle/hard timeout): the minute sweep (:func:`run_sweep`) ends the
  offending live session the same way. The window is one sweep (<= 60 s).
* **Usage**: summed from the existing ``guest_sessions`` byte counters of
  the subscriber's guest for the current period. A session that started
  before the period began counts in full (documented trade-off).

Everything here is a no-op while ``ISP_PARTNER_ENFORCEMENT_ENABLED`` is off.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from .config import get_isp_partner_settings

logger = logging.getLogger(__name__)

MB = 1024 * 1024

EVENT_KINDS = frozenset(
    {
        "fup_throttle",
        "fup_restore",
        "fup_topup",
        "fup_reset",
        "boost_on",
        "boost_off",
        "mac_bound",
        "mac_reject",
        "ip_reject",
        "concurrency",
        "idle_timeout",
        "hard_timeout",
        "validity_start",
        "reauth",
    }
)


# --------------------------------------------------------------------------
# Pure helpers (unit-tested without a database)
# --------------------------------------------------------------------------


def _tz(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "Asia/Kolkata")
    except Exception:  # noqa: BLE001
        return ZoneInfo("Asia/Kolkata")


def boost_active(
    start_minute: int | None, end_minute: int | None, now: datetime, tz: str | None
) -> bool:
    """True while ``now`` (any tz) is inside [start, end) local minutes.
    ``end < start`` wraps midnight; ``start == end`` is never active."""
    if start_minute is None or end_minute is None or start_minute == end_minute:
        return False
    local = now.astimezone(_tz(tz))
    m = local.hour * 60 + local.minute
    if start_minute < end_minute:
        return start_minute <= m < end_minute
    return m >= start_minute or m < end_minute


def fup_period(
    reset: str,
    *,
    now: datetime,
    tz: str | None,
    valid_until: datetime | None,
    validity_days: int | None,
) -> tuple[datetime, datetime]:
    """The current FUP period [start, end) in UTC.

    ``cycle`` follows the subscriber's validity (``valid_until`` minus
    ``validity_days``); without a validity it falls back to the calendar
    month, which is also what ``month`` means. ``day`` is local midnight to
    midnight."""
    zone = _tz(tz)
    local = now.astimezone(zone)
    if reset == "day":
        start = datetime.combine(local.date(), time(0), zone)
        return start.astimezone(UTC), (start + timedelta(days=1)).astimezone(UTC)
    if reset == "cycle" and valid_until is not None and validity_days:
        end = valid_until
        start = end - timedelta(days=validity_days)
        # Past the end (expired, or renewed but not yet recomputed): roll
        # forward whole cycles so the period always contains ``now``.
        while now >= end:
            start, end = end, end + timedelta(days=validity_days)
        while now < start:
            start, end = start - timedelta(days=validity_days), start
        return start.astimezone(UTC), end.astimezone(UTC)
    first = date(local.year, local.month, 1)
    nxt = date(local.year + (local.month == 12), local.month % 12 + 1, 1)
    return (
        datetime.combine(first, time(0), zone).astimezone(UTC),
        datetime.combine(nxt, time(0), zone).astimezone(UTC),
    )


def allowance_bytes(limit_mb: int | None) -> int | None:
    return None if not limit_mb else int(limit_mb) * MB


def carried_forward(
    *, allowance: int | None, used: int, carry_in: int, topup: int
) -> int:
    """Unused bytes rolled into the next period, capped at one period's
    allowance (so a never-used account does not accumulate forever)."""
    if not allowance:
        return 0
    left = allowance + carry_in + topup - used
    return max(0, min(left, allowance))


def counted_bytes(down: int, up: int, *, exclude_upload: bool) -> int:
    return int(down) + (0 if exclude_upload else int(up))


def rate_from_group(group: Any, *, priority: int | None = None) -> str | None:
    """A RouterOS ``Mikrotik-Rate-Limit`` value from an ``IspSpeedGroup``,
    with the same grammar as ``queue_management.format_mikrotik_rate_limit``
    (rx = client upload, tx = client download). 0/0 = unlimited -> None.
    A package priority without a burst is reached with zero bursts, which
    RouterOS reads as "no burst"."""
    down, up = int(group.download_kbps or 0), int(group.upload_kbps or 0)
    if not down and not up:
        return None
    parts = [f"{up}k/{down}k"]
    has_burst = (
        getattr(group, "burst_upload_kbps", None) is not None
        or getattr(group, "burst_download_kbps", None) is not None
    )
    prio = priority or getattr(group, "priority", None) or 8
    if has_burst or priority:
        parts.append(
            f"{group.burst_upload_kbps or 0}k/{group.burst_download_kbps or 0}k"
            if has_burst
            else "0k/0k"
        )
        thr = (group.burst_threshold_kbps or 0) if has_burst else 0
        parts.append(f"{thr}k/{thr}k")
        bt = (group.burst_time_seconds or 0) if has_burst else 0
        parts.append(f"{bt}/{bt}")
        parts.append(str(prio))
    return " ".join(parts)


def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().upper().replace("-", ":")
    if len(m) == 12 and ":" not in m:
        m = ":".join(m[i : i + 2] for i in range(0, 12, 2))
    return m


@dataclass(frozen=True)
class SessionFacts:
    session_id: uuid.UUID
    started_at: datetime
    last_activity_at: datetime | None
    mac: str | None
    ip: str | None


@dataclass(frozen=True)
class AccessVerdict:
    session_id: uuid.UUID
    kind: str
    detail: str


def access_verdicts(
    policy: Any,
    sessions: list[SessionFacts],
    bound_macs: set[str],
    bound_ips: set[str],
    *,
    now: datetime,
) -> tuple[list[AccessVerdict], list[str]]:
    """Which live sessions to end, and which MACs to auto-bind.

    Order: hard/idle timeouts, then MAC, then IP, then concurrency (newest
    sessions beyond the limit go). Each session gets at most one verdict."""
    out: list[AccessVerdict] = []
    to_bind: list[str] = []
    ended: set[uuid.UUID] = set()
    macs = set(bound_macs)

    def end(s: SessionFacts, kind: str, detail: str) -> None:
        if s.session_id not in ended:
            ended.add(s.session_id)
            out.append(AccessVerdict(s.session_id, kind, detail))

    for s in sorted(sessions, key=lambda x: x.started_at):
        if policy.hard_timeout_s and (now - s.started_at).total_seconds() >= int(
            policy.hard_timeout_s
        ):
            end(s, "hard_timeout", f"{policy.hard_timeout_s}s")
            continue
        last = s.last_activity_at or s.started_at
        if policy.idle_timeout_s and (now - last).total_seconds() >= int(
            policy.idle_timeout_s
        ):
            end(s, "idle_timeout", f"{policy.idle_timeout_s}s")
            continue
        mac = norm_mac(s.mac)
        bind_n = int(policy.mac_bind_count or 0)
        if mac and bind_n > 0 and mac not in macs and len(macs) < bind_n:
            macs.add(mac)
            to_bind.append(mac)
        restrict = bool(policy.mac_restriction) or bind_n > 0
        if restrict and macs and (not mac or mac not in macs):
            end(s, "mac_reject", mac or "no MAC")
            continue
        if policy.ip_restriction and bound_ips and (s.ip or "") not in bound_ips:
            end(s, "ip_reject", s.ip or "no IP")
            continue
    if policy.max_simultaneous:
        alive = [
            s
            for s in sorted(sessions, key=lambda x: x.started_at)
            if s.session_id not in ended
        ]
        for s in alive[int(policy.max_simultaneous) :]:
            end(s, "concurrency", f"limit {policy.max_simultaneous}")
    return out, to_bind


# --------------------------------------------------------------------------
# Database side
# --------------------------------------------------------------------------


async def _policy_for_package(session: Any, package_id: uuid.UUID) -> Any:
    from .enforcement_models import IspPackagePolicy

    return (
        await session.execute(
            select(IspPackagePolicy).where(
                IspPackagePolicy.package_id == package_id,
                IspPackagePolicy.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


async def _org_tz(session: Any, organization_id: uuid.UUID) -> str | None:
    from app.domains.organization.models import Organization

    org = await session.get(Organization, organization_id)
    tz = getattr(org, "timezone", None)
    return None if not tz or tz == "UTC" else tz


async def effective_rate_override(
    session: Any,
    *,
    package_id: uuid.UUID,
    subscriber: Any | None,
    organization_id: uuid.UUID,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    """(override?, rate) for the X1 wrapper. ``override`` False means "use
    the package's own speed group as today". Throttle beats boost."""
    if not get_isp_partner_settings().enforcement_enabled:
        return False, None
    from .enforcement_models import IspSubscriberUsage
    from .plans_models import IspSpeedGroup

    policy = await _policy_for_package(session, package_id)
    if policy is None:
        return False, None
    now = now or datetime.now(UTC)
    group_id = None
    if subscriber is not None and policy.fup_fallback_speed_group_id:
        usage = (
            await session.execute(
                select(IspSubscriberUsage).where(
                    IspSubscriberUsage.subscriber_id == subscriber.id,
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
            now,
            await _org_tz(session, policy.isp_organization_id),
        )
    ):
        group_id = policy.boost_speed_group_id
    if group_id is None and not policy.queue_priority:
        return False, None
    if group_id is None:
        from .plans_models import IspPackage

        pkg = await session.get(IspPackage, package_id)
        group_id = pkg.speed_group_id if pkg else None
    group = await session.get(IspSpeedGroup, group_id) if group_id else None
    if group is None:
        return False, None
    return True, rate_from_group(group, priority=policy.queue_priority)


async def record_event(
    session: Any,
    *,
    isp_id: uuid.UUID,
    subscriber_id: uuid.UUID,
    kind: str,
    detail: str | None = None,
    session_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> None:
    from .enforcement_models import IspEnforcementEvent

    session.add(
        IspEnforcementEvent(
            isp_organization_id=isp_id,
            subscriber_id=subscriber_id,
            kind=kind,
            detail=(detail or "")[:255] or None,
            session_id=session_id,
            occurred_at=now or datetime.now(UTC),
        )
    )


async def compute_usage(
    session: Any, *, subscriber: Any, policy: Any, package: Any, now: datetime
) -> tuple[Any, bool | None]:
    """Recompute this subscriber's usage row. Returns (row, flipped) where
    flipped is True (newly throttled), False (newly restored) or None."""
    from app.domains.guest.models import GuestSession

    from .enforcement_models import IspSubscriberUsage

    tz = await _org_tz(session, subscriber.customer_organization_id)
    start, end = fup_period(
        policy.fup_reset,
        now=now,
        tz=tz,
        valid_until=subscriber.valid_until,
        validity_days=getattr(package, "validity_days", None),
    )
    row = (
        await session.execute(
            select(IspSubscriberUsage).where(
                IspSubscriberUsage.subscriber_id == subscriber.id,
                IspSubscriberUsage.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    allowance = allowance_bytes(policy.fup_limit_mb)
    if row is None:
        row = IspSubscriberUsage(
            isp_organization_id=subscriber.isp_organization_id,
            subscriber_id=subscriber.id,
            period_start=start,
            period_end=end,
            used_down_bytes=0,
            used_up_bytes=0,
            carry_bytes=0,
            topup_bytes=0,
            throttled=False,
        )
        session.add(row)
    elif row.period_start != start:
        prev_used = counted_bytes(
            row.used_down_bytes,
            row.used_up_bytes,
            exclude_upload=policy.fup_exclude_upload,
        )
        row.carry_bytes = (
            carried_forward(
                allowance=allowance,
                used=prev_used,
                carry_in=row.carry_bytes or 0,
                topup=row.topup_bytes or 0,
            )
            if policy.fup_carry_forward
            else 0
        )
        row.period_start, row.period_end, row.topup_bytes = start, end, 0
        await record_event(
            session,
            isp_id=subscriber.isp_organization_id,
            subscriber_id=subscriber.id,
            kind="fup_reset",
            detail=f"carry {row.carry_bytes // MB} MB",
            now=now,
        )
    down = up = 0
    if subscriber.guest_id is not None:
        down, up = (
            await session.execute(
                select(
                    func.coalesce(func.sum(GuestSession.bytes_downloaded), 0),
                    func.coalesce(func.sum(GuestSession.bytes_uploaded), 0),
                ).where(
                    GuestSession.guest_id == subscriber.guest_id,
                    GuestSession.organization_id == subscriber.customer_organization_id,
                    GuestSession.started_at >= start,
                    GuestSession.started_at < end,
                )
            )
        ).one()
    row.used_down_bytes, row.used_up_bytes = int(down), int(up)
    row.last_computed_at = now
    was = bool(row.throttled)
    used = counted_bytes(down, up, exclude_upload=policy.fup_exclude_upload)
    now_throttled = bool(
        allowance
        and used >= allowance + (row.carry_bytes or 0) + (row.topup_bytes or 0)
    )
    row.throttled = now_throttled
    if now_throttled and not was:
        row.throttled_at = now
        return row, True
    if was and not now_throttled:
        row.throttled_at = None
        return row, False
    return row, None


def fup_view(row: Any, policy: Any, groups: dict[uuid.UUID, str]) -> dict[str, Any]:
    """The FUP-status read the subscriber 360 page shows (contract in
    LANE_NOTES [JAZE-2])."""
    allowance = allowance_bytes(getattr(policy, "fup_limit_mb", None))
    if row is None:
        return {
            "fup_enabled": bool(allowance),
            "allowance_bytes": allowance,
            "used_bytes": 0,
            "used_down_bytes": 0,
            "used_up_bytes": 0,
            "carry_bytes": 0,
            "topup_bytes": 0,
            "remaining_bytes": allowance,
            "throttled": False,
            "throttled_at": None,
            "period_start": None,
            "period_end": None,
            "reset": getattr(policy, "fup_reset", None),
            "exclude_upload": bool(getattr(policy, "fup_exclude_upload", False)),
            "fallback_speed_group": None,
            "computed_at": None,
        }
    used = counted_bytes(
        row.used_down_bytes, row.used_up_bytes, exclude_upload=policy.fup_exclude_upload
    )
    total = (allowance or 0) + (row.carry_bytes or 0) + (row.topup_bytes or 0)
    fb = policy.fup_fallback_speed_group_id
    return {
        "fup_enabled": bool(allowance),
        "allowance_bytes": allowance,
        "used_bytes": used,
        "used_down_bytes": row.used_down_bytes,
        "used_up_bytes": row.used_up_bytes,
        "carry_bytes": row.carry_bytes,
        "topup_bytes": row.topup_bytes,
        "remaining_bytes": max(0, total - used) if allowance else None,
        "throttled": bool(row.throttled),
        "throttled_at": row.throttled_at.isoformat() if row.throttled_at else None,
        "period_start": row.period_start.isoformat(),
        "period_end": row.period_end.isoformat(),
        "reset": policy.fup_reset,
        "exclude_upload": bool(policy.fup_exclude_upload),
        "fallback_speed_group": (
            {"id": str(fb), "name": groups.get(fb)} if fb else None
        ),
        "computed_at": row.last_computed_at.isoformat()
        if row.last_computed_at
        else None,
    }

"""P1-2: billing cycle linked to the package (today) or to the subscriber.

``package`` (the default, and what "no row" means): a renewal runs
``validity_days x cycles`` from ``max(now, valid_until)``, exactly as JAZE-1 /
BILL-2 compute it.

``subscriber``: the same end, then snapped to the subscriber's
``billing_anchor_day`` (J2 profile field, 1-28): the anchor-day date nearest
to that end in the ISP's timezone (a tie goes to the later date), at the same
local time of day. An on-time renewal of a subscriber already on the anchor
stays on it month after month; a first renewal moves by at most about 15
days. The price is not changed (pro-rating is a founder question).

``cycle_end`` is the only thing ``plans_service.recharge`` calls. It returns
the old ``end`` unchanged unless all of these hold: ``ISP_CYCLE_BASIS_ENABLED``
is on, the package has a ``subscriber`` row, the package validity is at least
28 days (a daily or weekly pack never snaps to a monthly day), and the
subscriber has an anchor day.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select

from .p1_config import get_p1_settings
from .p1_models import IspPackageCycleBasis

__all__ = ["MIN_SNAP_VALIDITY_DAYS", "cycle_end", "package_basis", "snap_to_anchor"]

MIN_SNAP_VALIDITY_DAYS = 28
_DEFAULT_TZ = "Asia/Kolkata"


def _tz(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or _DEFAULT_TZ)
    except Exception:  # noqa: BLE001 -- bad tz name: the ISP default
        return ZoneInfo(_DEFAULT_TZ)


def _shift_month(d: date, months: int) -> tuple[int, int]:
    n = d.year * 12 + (d.month - 1) + months
    return n // 12, n % 12 + 1


def snap_to_anchor(end: datetime, anchor_day: int, tz_name: str | None) -> datetime:
    """The anchor-day datetime nearest to ``end`` (same local time; ties ->
    later). ``anchor_day`` is 1-28, so it exists in every month."""
    tz = _tz(tz_name)
    local = end.astimezone(tz)
    best: datetime | None = None
    for months in (-1, 0, 1):
        y, m = _shift_month(local.date(), months)
        cand = local.replace(year=y, month=m, day=anchor_day)
        if best is None:
            best = cand
            continue
        if abs(cand - local) < abs(best - local) or (
            abs(cand - local) == abs(best - local) and cand > best
        ):
            best = cand
    assert best is not None
    # keep the original tz-awareness (UTC in, UTC out)
    return best.astimezone(end.tzinfo) if end.tzinfo else best


async def package_basis(session: Any, package_id: uuid.UUID) -> str:
    row = (
        await session.execute(
            select(IspPackageCycleBasis.basis).where(
                IspPackageCycleBasis.package_id == package_id,
                IspPackageCycleBasis.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    return row or "package"


async def cycle_end(
    session: Any,
    isp: Any,
    subscriber: Any,
    package: Any,
    start: datetime,
    end: datetime,
) -> datetime:
    """Identity unless the flag, the package basis, the validity and the
    subscriber's anchor day all say "snap" (see the module docstring)."""
    if not get_p1_settings().cycle_basis_enabled:
        return end
    if (package.validity_days or 0) < MIN_SNAP_VALIDITY_DAYS:
        return end
    if await package_basis(session, package.id) != "subscriber":
        return end
    from .subscriber360_models import IspSubscriberProfile

    anchor = (
        await session.execute(
            select(IspSubscriberProfile.billing_anchor_day).where(
                IspSubscriberProfile.subscriber_id == subscriber.id,
                IspSubscriberProfile.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if not anchor or not 1 <= int(anchor) <= 28:  # noqa: PLR2004
        return end
    tz_name = getattr(getattr(isp, "organization", None), "timezone", None)
    snapped = snap_to_anchor(end, int(anchor), tz_name)
    # never shorter than half the package validity (cannot happen for >= 28
    # days and a nearest-anchor snap, kept as a hard floor)
    floor = start + timedelta(days=package.validity_days / 2)
    return snapped if snapped > floor else end

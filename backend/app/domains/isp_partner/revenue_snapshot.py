"""SMALL-4: MRR history (daily snapshots) and DSO for the revenue hub.

Behind REVENUE-HUB's flag ``ISP_REVENUE_HUB_ENABLED`` (off: the daily task
writes nothing and the hub is 404 anyway).

* **Snapshot.** The daily ISP task (``tasks._billing_daily_one``, one guarded
  call per ISP in its own transaction, BE-HARDEN) calls ``take_snapshot``,
  which runs the hub's own ``summary`` for the whole ISP (system context: no
  zone, no package, no confinement) and stores MRR, ARPU, active, pending,
  expired, churned, unpriced, month-to-date billed and collected, open dues,
  trailing-90-day sales and DSO for the ISP-local day. Idempotent: one row
  per (ISP, day); a re-run the same day overwrites that day's row.
* **Trend.** Each month in ``summary.trend`` gets ``mrr_paise`` /
  ``arpu_paise`` / ``active`` / ``mrr_source``: the last snapshot taken in
  that month (``snapshot``); else, for the month in progress, today's live
  MRR (``live``); else that month's billed taxable value as a proxy
  (``billed_proxy``, ARPU and active then null). Snapshots are whole-ISP, so
  any zone / package / header-zone filter or a confined caller always gets
  ``live`` / ``billed_proxy``.
* **DSO** (days sales outstanding), standard trailing-period form:
  ``DSO = open subscriber dues / net billed in the last 90 days x 90``.
  Dues = balances of open subscriber invoices (GST incl.); net billed =
  subscriber invoices issued in the 90 ISP-local days up to today, total
  less credit notes, not cancelled (GST incl., so both sides match). Null
  when nothing was billed. Same filters / scope as the rest of the hub.
"""

from __future__ import annotations

from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy import select

from .revenue_snapshot_models import IspRevenueSnapshot

DSO_DAYS = 90


def dso(dues_paise: int, sales_paise: int, days: int = DSO_DAYS) -> Decimal | None:
    if sales_paise <= 0:
        return None
    return (Decimal(dues_paise) * days / Decimal(sales_paise)).quantize(
        Decimal("0.1"), rounding=ROUND_HALF_UP
    )


async def take_snapshot(session: Any, isp: Any) -> IspRevenueSnapshot | None:
    """Upsert today's row for ``isp`` (a system context). Flag off -> None."""
    from .revenue_router import get_revenue_settings
    from .revenue_service import IspRevenueService, RevFilters

    if not get_revenue_settings().revenue_hub_enabled:
        return None
    svc = IspRevenueService(session)
    s = await svc.summary(isp, RevFilters(months=1))
    k = s["kpis"]
    day = date.fromisoformat(s["today"])
    row = (
        await session.execute(
            select(IspRevenueSnapshot)
            .where(
                IspRevenueSnapshot.isp_organization_id == isp.isp_org_id,
                IspRevenueSnapshot.snapshot_date == day,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspRevenueSnapshot(isp_organization_id=isp.isp_org_id, snapshot_date=day)
        session.add(row)
    row.mrr_paise = k["mrr_paise"]
    row.arpu_paise = k["arpu_paise"]
    row.active = k["active"]
    row.pending = k["pending"]
    row.expired = k["expired"]
    row.churned = k["churned"]
    row.unpriced = k["unpriced"]
    row.billed_month_paise = k["billed_paise"]
    row.collected_month_paise = k["collected_paise"]
    row.dues_paise = k["dues_paise"]
    row.sales_90d_paise = k["sales_90d_paise"]
    row.dso_days = dso(k["dues_paise"], k["sales_90d_paise"])
    await session.flush()
    return row


async def month_snapshots(
    session: Any, isp_org_id: Any, first: date, last: date
) -> dict[str, IspRevenueSnapshot]:
    """month key -> the last snapshot dated in that month, for months in
    [first, last] (first days)."""
    from . import revenue_logic as logic

    rows = (
        (
            await session.execute(
                select(IspRevenueSnapshot)
                .where(
                    IspRevenueSnapshot.isp_organization_id == isp_org_id,
                    IspRevenueSnapshot.is_deleted.is_(False),
                    IspRevenueSnapshot.snapshot_date >= first,
                    IspRevenueSnapshot.snapshot_date < logic.add_months(last, 1),
                )
                .order_by(IspRevenueSnapshot.snapshot_date)
            )
        )
        .scalars()
        .all()
    )
    out: dict[str, IspRevenueSnapshot] = {}
    for r in rows:
        out[logic.month_key(r.snapshot_date)] = r  # later days overwrite
    return out


def apply_to_trend(
    trend: list[dict[str, Any]],
    snaps: dict[str, IspRevenueSnapshot] | None,
    *,
    live_mrr: int,
    live_arpu: int | None,
    live_active: int,
) -> None:
    """Add mrr_paise / arpu_paise / active / mrr_source to each trend row.
    ``snaps`` None = snapshots not usable for this view (filtered/confined)."""
    for t in trend:
        snap = (snaps or {}).get(t["month"])
        if snap is not None:
            t.update(
                mrr_paise=snap.mrr_paise,
                arpu_paise=snap.arpu_paise,
                active=snap.active,
                mrr_source="snapshot",
                snapshot_date=snap.snapshot_date.isoformat(),
            )
        elif t["partial"]:
            t.update(
                mrr_paise=live_mrr,
                arpu_paise=live_arpu,
                active=live_active,
                mrr_source="live",
                snapshot_date=None,
            )
        else:
            t.update(
                mrr_paise=t["billed_paise"],
                arpu_paise=None,
                active=None,
                mrr_source="billed_proxy",
                snapshot_date=None,
            )


def sales_since(today: date) -> date:
    return today - timedelta(days=DSO_DAYS - 1)


__all__ = [
    "DSO_DAYS",
    "apply_to_trend",
    "dso",
    "month_snapshots",
    "sales_since",
    "take_snapshot",
]

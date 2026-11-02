"""REVENUE-HUB + CHURN-RISK: one read-only metrics service over data we
already hold (rules and definitions in ``revenue_logic``).

**In view** = the ISP's subscribers / subscriber invoices under the caller's
customers (``isp.child_ids()``: confinement, already narrowed by ZONE-1's
``scope_zone_id``; the ORM selects of ``isp_subscribers`` and ``isp_invoices``
also carry ZONE-1's zone criterion), then the hub's own optional filters:
``zone_id`` / ``no_zone`` (the attributed zone, exact) and ``package_id``.

Nothing is written. Every tile and its drill-down list are computed from the
same rows, so a list's ``total`` is the tile's number.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from sqlalchemy import func, or_, select

from . import dashboard_logic as dash_logic
from . import revenue_logic as logic
from .dashboard_service import kyc_pending_ids
from .dependencies import IspContext
from .exceptions import IspBadRequestError, IspZoneNotFoundError

OPEN_STATUSES = ("issued", "partially_paid")


@dataclass(frozen=True)
class RevFilters:
    month: str | None = None
    months: int = 6
    zone_id: uuid.UUID | None = None
    no_zone: bool = False
    package_id: uuid.UUID | None = None


class IspRevenueService:
    def __init__(self, session: Any, *, clock: Any = None) -> None:
        self.session = session
        self._clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------ base

    async def _base(self, isp: IspContext, f: RevFilters) -> dict[str, Any]:
        from .billing_models import IspBillingSettings, IspZone
        from .compliance_service import compliance_settings
        from .models import IspCustomerProfile
        from .plans_models import IspPackage

        now = self._clock()
        tz = getattr(isp.organization, "timezone", None) or "Asia/Kolkata"
        today = logic.local_date(now, tz)
        try:
            month = logic.parse_month(f.month, today)
        except ValueError as exc:
            raise IspBadRequestError(
                "month is YYYY-MM", reason="ISP_QUERY_INVALID"
            ) from exc
        if month > logic.month_start(today):
            raise IspBadRequestError(
                "month cannot be in the future", reason="ISP_MONTH_IN_FUTURE"
            )
        if not 1 <= f.months <= 24:
            raise IspBadRequestError("months is 1 to 24", reason="ISP_QUERY_INVALID")
        if f.zone_id is not None and f.no_zone:
            raise IspBadRequestError(
                "Pick a zone or 'no zone', not both", reason="ISP_QUERY_INVALID"
            )
        if f.zone_id is not None:
            z = await self.session.get(IspZone, f.zone_id)
            if z is None or z.is_deleted or z.isp_organization_id != isp.isp_org_id:
                raise IspZoneNotFoundError()
        if f.package_id is not None:
            from .plans_service import IspPackageNotFoundError

            p = await self.session.get(IspPackage, f.package_id)
            if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
                raise IspPackageNotFoundError()
        children = await isp.child_ids()
        settings = (
            await self.session.execute(
                select(IspBillingSettings).where(
                    IspBillingSettings.isp_organization_id == isp.isp_org_id,
                    IspBillingSettings.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        cust_zone: dict[uuid.UUID, uuid.UUID | None] = {}
        if children:
            cust_zone = dict(
                (
                    await self.session.execute(
                        select(
                            IspCustomerProfile.customer_organization_id,
                            IspCustomerProfile.zone_id,
                        ).where(
                            IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                            IspCustomerProfile.customer_organization_id.in_(children),
                        )
                    )
                ).all()
            )
        churn_days = (
            await compliance_settings(self.session, isp.isp_org_id)
        ).churn_after_days
        return {
            "now": now,
            "tz": tz,
            "today": today,
            "month": month,
            "children": children,
            "cust_zone": cust_zone,
            "gst_applied": bool(settings and settings.gst_enabled),
            "rate_bp": int(settings.gst_rate_bp) if settings else 0,
            "churn_after": timedelta(days=churn_days),
            "churn_after_days": churn_days,
        }

    def _zone_ok(self, f: RevFilters, zone: uuid.UUID | None) -> bool:
        if f.no_zone:
            return zone is None
        if f.zone_id is not None:
            return zone == f.zone_id
        return True

    async def _subscribers(
        self, isp: IspContext, f: RevFilters, b: dict[str, Any]
    ) -> list[dict[str, Any]]:
        from .plans_models import IspPackage, IspSubscriber
        from .subscriber360_models import IspSubscriberProfile
        from .subscriber360_service import IspSubscriber360Service

        if not b["children"]:
            return []
        q = (
            select(IspSubscriber, IspSubscriberProfile, IspPackage)
            .outerjoin(
                IspSubscriberProfile,
                (IspSubscriberProfile.subscriber_id == IspSubscriber.id)
                & IspSubscriberProfile.is_deleted.is_(False),
            )
            .outerjoin(IspPackage, IspPackage.id == IspSubscriber.package_id)
            .where(
                IspSubscriber.isp_organization_id == isp.isp_org_id,
                IspSubscriber.customer_organization_id.in_(b["children"]),
                IspSubscriber.is_deleted.is_(False),
            )
        )
        if f.package_id is not None:
            q = q.where(IspSubscriber.package_id == f.package_id)
        found = (await self.session.execute(q)).all()
        suspended = await IspSubscriber360Service._suspended_customers(
            SimpleNamespace(session=self.session),
            sorted({s.customer_organization_id for s, _p, _k in found}),
        )
        now, churn_after = b["now"], b["churn_after"]
        kyc_pending = await kyc_pending_ids(self.session, [s.id for s, _p, _k in found])
        clock = SimpleNamespace(now=lambda: now)
        rows = []
        for s, p, pkg in found:
            zone = s.zone_id or b["cust_zone"].get(s.customer_organization_id)
            if not self._zone_ok(f, zone):
                continue
            display = IspSubscriber360Service.display_state(
                clock, s, p, customer_suspended=s.customer_organization_id in suspended
            )
            bucket = dash_logic.bucket_of(
                display,
                valid_until=s.valid_until,
                now=now,
                churn_after=churn_after,
                kyc_pending=s.id in kyc_pending,
            )
            state = logic.state_of(bucket)
            price = None
            if pkg is not None:
                price = (
                    p.override_price_paise
                    if p is not None and p.override_price_paise is not None
                    else pkg.price_paise
                )
            mrr = (
                logic.monthly_paise(
                    price,
                    pkg.validity_days if pkg is not None else None,
                    includes_gst=bool(pkg.price_includes_gst) if pkg else False,
                    gst_applied=b["gst_applied"],
                    rate_bp=b["rate_bp"],
                )
                if state == "active"
                else None
            )
            rows.append(
                {
                    "sub": s,
                    "package": pkg,
                    "zone_id": zone,
                    "display_state": display,
                    "state": state,
                    "mrr": mrr,
                    "churned_at": logic.churned_at(state, s.valid_until, churn_after),
                }
            )
        return rows

    async def _invoice_months(
        self, isp: IspContext, f: RevFilters, b: dict[str, Any], since: date
    ) -> list[dict[str, Any]]:
        """Subscriber invoices issued since ``since`` grouped by (month,
        attributed zone)."""
        from .billing_models import IspInvoice

        if not b["children"]:
            return []
        # extract() on the date column itself: date_trunc would cast the date
        # to timestamptz in the session time zone and can shift the month.
        y = func.extract("year", IspInvoice.issue_date).label("y")
        m = func.extract("month", IspInvoice.issue_date).label("m")
        q = (
            select(
                y,
                m,
                IspInvoice.zone_id,
                IspInvoice.customer_organization_id,
                func.count(),
                func.coalesce(func.sum(IspInvoice.taxable_paise), 0),
                func.coalesce(
                    func.sum(IspInvoice.total_paise - IspInvoice.credit_noted_paise), 0
                ),
                func.coalesce(func.sum(IspInvoice.paid_paise), 0),
            )
            .where(*self._invoice_where(isp, f, b), IspInvoice.issue_date >= since)
            .group_by(y, m, IspInvoice.zone_id, IspInvoice.customer_organization_id)
        )
        out = []
        for year, month, zid, cust, n, taxable, net, paid in (
            await self.session.execute(q)
        ).all():
            zone = zid or b["cust_zone"].get(cust)
            if not self._zone_ok(f, zone):
                continue
            out.append(
                {
                    "month": f"{int(year):04d}-{int(month):02d}",
                    "zone_id": zone,
                    "count": int(n),
                    "taxable": int(taxable),
                    "net": int(net),
                    "paid": int(paid),
                }
            )
        return out

    def _invoice_where(
        self, isp: IspContext, f: RevFilters, b: dict[str, Any]
    ) -> list[Any]:
        from .billing_models import IspInvoice, IspInvoiceLine

        where = [
            IspInvoice.isp_organization_id == isp.isp_org_id,
            IspInvoice.bill_to_kind == "subscriber",
            IspInvoice.doc_type == "invoice",
            IspInvoice.status != "cancelled",
            IspInvoice.is_deleted.is_(False),
            IspInvoice.customer_organization_id.in_(b["children"]),
        ]
        if f.package_id is not None:
            where.append(
                IspInvoice.id.in_(
                    select(IspInvoiceLine.invoice_id).where(
                        IspInvoiceLine.package_id == f.package_id
                    )
                )
            )
        return where

    async def _open_invoices(
        self, isp: IspContext, f: RevFilters, b: dict[str, Any], *, month: date | None
    ) -> list[tuple[Any, uuid.UUID | None]]:
        """Open subscriber invoices with a balance (or, with ``month``, every
        invoice issued in that month that still has a balance)."""
        from .billing_models import IspInvoice

        if not b["children"]:
            return []
        q = select(IspInvoice).where(
            *self._invoice_where(isp, f, b),
            IspInvoice.total_paise
            - IspInvoice.paid_paise
            - IspInvoice.credit_noted_paise
            > 0,
        )
        if month is None:
            q = q.where(IspInvoice.status.in_(OPEN_STATUSES))
        else:
            q = q.where(
                IspInvoice.issue_date >= month,
                IspInvoice.issue_date < logic.add_months(month, 1),
            )
        out = []
        for inv in (await self.session.execute(q)).scalars().all():
            zone = inv.zone_id or b["cust_zone"].get(inv.customer_organization_id)
            if self._zone_ok(f, zone):
                out.append((inv, zone))
        return out

    # --------------------------------------------------------------- summary

    async def summary(self, isp: IspContext, f: RevFilters) -> dict[str, Any]:
        from .billing_models import IspZone
        from .billing_service import balance_of

        b = await self._base(isp, f)
        rows = await self._subscribers(isp, f, b)
        month, tz, now = b["month"], b["tz"], b["now"]
        first = logic.add_months(month, -(f.months - 1))
        inv_months = await self._invoice_months(isp, f, b, first)
        open_invs = await self._open_invoices(isp, f, b, month=None)

        counts = dict.fromkeys(logic.STATES, 0)
        unpriced = 0
        mrr = 0
        for r in rows:
            counts[r["state"]] += 1
            if r["state"] == "active":
                if r["mrr"] is None:
                    unpriced += 1
                else:
                    mrr += r["mrr"]
        active = counts["active"]

        # trend: new / lost / base / churn rate, billed / collected
        created = [(r["sub"].created_at, r["churned_at"]) for r in rows]
        by_month: dict[str, dict[str, int]] = defaultdict(
            lambda: {"count": 0, "taxable": 0, "net": 0, "paid": 0}
        )
        for x in inv_months:
            agg = by_month[x["month"]]
            for k in ("count", "taxable", "net", "paid"):
                agg[k] += x[k]
        trend = []
        for i in range(f.months):
            m0 = logic.add_months(first, i)
            start, end = logic.month_bounds(m0, tz)
            new = sum(
                1
                for r in rows
                if r["sub"].created_at and start <= r["sub"].created_at < end
            )
            lost = sum(
                1 for r in rows if r["churned_at"] and start <= r["churned_at"] < end
            )
            base = logic.base_at(created, start)
            agg = by_month[logic.month_key(m0)]
            trend.append(
                {
                    "month": logic.month_key(m0),
                    "partial": end > now,
                    "new": new,
                    "lost": lost,
                    "net": new - lost,
                    "base_at_start": base,
                    "churn_rate": logic.rate(lost, base),
                    "invoices": agg["count"],
                    "billed_paise": agg["taxable"],
                    "net_billed_paise": agg["net"],
                    "collected_paise": agg["paid"],
                    "collection_rate": logic.rate(agg["paid"], agg["net"]),
                }
            )
        current = trend[-1]

        # SMALL-4: MRR history from daily snapshots (whole-ISP views only)
        from . import revenue_snapshot as snap
        from .zones_scope import current_scope

        whole_isp = (
            isp.confined_customer_ids is None
            and current_scope(self.session) is None
            and f.zone_id is None
            and not f.no_zone
            and f.package_id is None
        )
        snap.apply_to_trend(
            trend,
            await snap.month_snapshots(self.session, isp.isp_org_id, first, month)
            if whole_isp
            else None,
            live_mrr=mrr,
            live_arpu=mrr // active if active else None,
            live_active=active,
        )
        sales_90d = sum(
            x["net"]
            for x in await self._invoice_months(isp, f, b, snap.sales_since(b["today"]))
        )

        # dues ageing
        ageing = {k: {"invoices": 0, "amount_paise": 0} for k in logic.AGEING}
        for inv, _zone in open_invs:
            k = logic.ageing_bucket(inv.due_date, b["today"])
            ageing[k]["invoices"] += 1
            ageing[k]["amount_paise"] += balance_of(inv)

        dso = snap.dso(sum(v["amount_paise"] for v in ageing.values()), sales_90d)

        # zone leaderboard
        zones: dict[uuid.UUID | None, dict[str, Any]] = {}

        def zrow(zid: uuid.UUID | None) -> dict[str, Any]:
            if zid not in zones:
                zones[zid] = {
                    "zone_id": str(zid) if zid else None,
                    "name": None,
                    "active": 0,
                    "churned": 0,
                    "mrr_paise": 0,
                    "billed_paise": 0,
                    "net_billed_paise": 0,
                    "collected_paise": 0,
                    "dues_paise": 0,
                }
            return zones[zid]

        for r in rows:
            z = zrow(r["zone_id"])
            if r["state"] == "active":
                z["active"] += 1
                z["mrr_paise"] += r["mrr"] or 0
            elif r["state"] == "churned":
                z["churned"] += 1
        mk = logic.month_key(month)
        for x in inv_months:
            if x["month"] != mk:
                continue
            z = zrow(x["zone_id"])
            z["billed_paise"] += x["taxable"]
            z["net_billed_paise"] += x["net"]
            z["collected_paise"] += x["paid"]
        for inv, zone in open_invs:
            zrow(zone)["dues_paise"] += balance_of(inv)
        named = [z for z in zones if z is not None]
        names = {}
        if named:
            names = dict(
                (
                    await self.session.execute(
                        select(IspZone.id, IspZone.name).where(IspZone.id.in_(named))
                    )
                ).all()
            )
        wallets = await self._wallets(isp, named)
        board = []
        for zid, z in zones.items():
            z["name"] = names.get(zid) if zid else None
            z["arpu_paise"] = z["mrr_paise"] // z["active"] if z["active"] else None
            z["collection_rate"] = logic.rate(
                z["collected_paise"], z["net_billed_paise"]
            )
            z["wallet_balance_paise"] = (
                wallets.get(zid) if wallets is not None else None
            )
            board.append(z)
        board.sort(
            key=lambda z: (-z["mrr_paise"], z["zone_id"] is None, z["name"] or "")
        )

        # package mix (active subscribers, current package)
        pk: dict[uuid.UUID | None, dict[str, Any]] = {}
        for r in rows:
            if r["state"] != "active":
                continue
            pkg = r["package"]
            key = pkg.id if pkg is not None else None
            e = pk.setdefault(
                key,
                {
                    "package_id": str(key) if key else None,
                    "name": pkg.name if pkg is not None else None,
                    "type": pkg.type if pkg is not None else None,
                    "active": 0,
                    "mrr_paise": 0,
                    "unpriced": 0,
                },
            )
            e["active"] += 1
            if r["mrr"] is None:
                e["unpriced"] += 1
            else:
                e["mrr_paise"] += r["mrr"]
        mix = sorted(pk.values(), key=lambda e: (-e["mrr_paise"], -e["active"]))
        for e in mix:
            e["mrr_share"] = logic.rate(e["mrr_paise"], mrr)
            e["active_share"] = logic.rate(e["active"], active)

        return {
            "as_of": now.isoformat(),
            "month": mk,
            "months": f.months,
            "churn_after_days": b["churn_after_days"],
            "gst_exclusive": True,
            "kpis": {
                "mrr_paise": mrr,
                "arpu_paise": mrr // active if active else None,
                "active": active,
                "pending": counts["pending"],
                "expired": counts["expired"],
                "churned": counts["churned"],
                "other": counts["other"],
                "total": len(rows),
                "unpriced": unpriced,
                "new": current["new"],
                "lost": current["lost"],
                "churn_rate": current["churn_rate"],
                "billed_paise": current["billed_paise"],
                "net_billed_paise": current["net_billed_paise"],
                "collected_paise": current["collected_paise"],
                "collection_rate": current["collection_rate"],
                "uncollected_paise": current["net_billed_paise"]
                - current["collected_paise"],
                "dues_paise": sum(v["amount_paise"] for v in ageing.values()),
                # SMALL-4: DSO over the trailing 90 days (see revenue_snapshot)
                "sales_90d_paise": sales_90d,
                "dso_days": float(dso) if dso is not None else None,
            },
            "today": b["today"].isoformat(),
            "mrr_history": {
                "snapshots_used": whole_isp,
                "dso_window_days": snap.DSO_DAYS,
            },
            "ageing": ageing,
            "trend": trend,
            "zones": board,
            "packages": mix,
            "definitions": logic.DEFINITIONS,
        }

    async def _wallets(
        self, isp: IspContext, zone_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, int] | None:
        """JAZE-4 zone wallet balances, or None while the ledger is off or the
        caller is confined (a wallet is ISP-wide, not per customer)."""
        from .finance_config import get_finance_settings
        from .finance_models import IspZoneLedgerEntry

        if not get_finance_settings().zone_ledger_enabled:
            return None
        if isp.confined_customer_ids is not None:
            return None
        if not zone_ids:
            return {}
        rows = (
            await self.session.execute(
                select(
                    IspZoneLedgerEntry.zone_id,
                    func.coalesce(func.sum(IspZoneLedgerEntry.amount_paise), 0),
                )
                .where(
                    IspZoneLedgerEntry.isp_organization_id == isp.isp_org_id,
                    IspZoneLedgerEntry.zone_id.in_(zone_ids),
                    IspZoneLedgerEntry.is_deleted.is_(False),
                )
                .group_by(IspZoneLedgerEntry.zone_id)
            )
        ).all()
        out = dict.fromkeys(zone_ids, 0)
        out.update({z: int(v) for z, v in rows})
        return out

    # ----------------------------------------------------------- drill-downs

    async def _names(
        self, customers: set[uuid.UUID], packages: set[uuid.UUID], zones: set[Any]
    ) -> tuple[dict, dict, dict]:
        from app.domains.organization.models import Organization

        from .billing_models import IspZone
        from .plans_models import IspPackage

        async def m(model: Any, col: Any, ids: set) -> dict:
            ids = {i for i in ids if i}
            if not ids:
                return {}
            return dict(
                (
                    await self.session.execute(
                        select(model.id, col).where(model.id.in_(ids))
                    )
                ).all()
            )

        return (
            await m(Organization, Organization.name, customers),
            await m(IspPackage, IspPackage.name, packages),
            await m(IspZone, IspZone.name, zones),
        )

    def _sub_item(self, r: dict[str, Any], names: tuple[dict, dict, dict]) -> dict:
        from .subscriber_identity import subscriber_identifier

        s = r["sub"]
        custs, pkgs, zones = names
        return {
            "id": str(s.id),
            "identifier": subscriber_identifier(s.identifier, s.source),
            "display_name": s.display_name
            or " ".join(p for p in (s.first_name, s.last_name) if p)
            or None,
            "phone": s.phone,
            "circuit_id": s.circuit_id,
            "customer_id": str(s.customer_organization_id),
            "customer_name": custs.get(s.customer_organization_id),
            "zone_id": str(r["zone_id"]) if r["zone_id"] else None,
            "zone_name": zones.get(r["zone_id"]) if r["zone_id"] else None,
            "package_id": str(s.package_id) if s.package_id else None,
            "package_name": pkgs.get(s.package_id) if s.package_id else None,
            "display_state": r["display_state"],
            "state": r["state"],
            "mrr_paise": r["mrr"],
            "valid_until": s.valid_until.isoformat() if s.valid_until else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "churned_at": r["churned_at"].isoformat() if r["churned_at"] else None,
        }

    async def drill(
        self,
        isp: IspContext,
        f: RevFilters,
        *,
        metric: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        from .billing_service import balance_of
        from .plans_models import IspSubscriber
        from .subscriber_identity import subscriber_identifier

        if metric not in logic.LIST_METRICS:
            raise IspBadRequestError("Unknown metric", reason="ISP_QUERY_INVALID")
        b = await self._base(isp, f)
        month = b["month"]
        if metric in logic.SUBSCRIBER_METRICS:
            rows = await self._subscribers(isp, f, b)
            start, end = logic.month_bounds(month, b["tz"])
            if metric == "unpriced":
                rows = [r for r in rows if r["state"] == "active" and r["mrr"] is None]
            elif metric == "new":
                rows = [
                    r
                    for r in rows
                    if r["sub"].created_at and start <= r["sub"].created_at < end
                ]
            elif metric == "lost":
                rows = [
                    r
                    for r in rows
                    if r["churned_at"] and start <= r["churned_at"] < end
                ]
            else:
                rows = [r for r in rows if r["state"] == metric]
            rows.sort(
                key=lambda r: (
                    -(r["mrr"] or 0),
                    r["sub"].circuit_id or 0,
                    str(r["sub"].id),
                )
            )
            total = len(rows)
            chunk = rows[(page - 1) * page_size : page * page_size]
            names = await self._names(
                {r["sub"].customer_organization_id for r in chunk},
                {r["sub"].package_id for r in chunk},
                {r["zone_id"] for r in chunk},
            )
            items = [self._sub_item(r, names) for r in chunk]
            kind = "subscribers"
        else:
            if metric == "uncollected":
                invs = await self._open_invoices(isp, f, b, month=month)
            else:
                bucket = metric.removeprefix("dues_")
                invs = [
                    (i, z)
                    for i, z in await self._open_invoices(isp, f, b, month=None)
                    if logic.ageing_bucket(i.due_date, b["today"]) == bucket
                ]
            invs.sort(key=lambda x: (x[0].due_date, x[0].number))
            total = len(invs)
            chunk = invs[(page - 1) * page_size : page * page_size]
            sub_ids = {i.subscriber_id for i, _z in chunk if i.subscriber_id}
            subs = {}
            if sub_ids:
                subs = {
                    s.id: s
                    for s in (
                        await self.session.execute(
                            select(IspSubscriber).where(IspSubscriber.id.in_(sub_ids))
                        )
                    )
                    .scalars()
                    .all()
                }
            custs, _p, zones = await self._names(
                {
                    i.customer_organization_id
                    for i, _z in chunk
                    if i.customer_organization_id
                },
                set(),
                {z for _i, z in chunk},
            )
            items = []
            for inv, zone in chunk:
                s = subs.get(inv.subscriber_id)
                items.append(
                    {
                        "invoice_id": str(inv.id),
                        "number": inv.number,
                        "issue_date": inv.issue_date.isoformat(),
                        "due_date": inv.due_date.isoformat(),
                        "days_past_due": (b["today"] - inv.due_date).days,
                        "total_paise": inv.total_paise,
                        "balance_paise": balance_of(inv),
                        "subscriber_id": str(inv.subscriber_id)
                        if inv.subscriber_id
                        else None,
                        "identifier": subscriber_identifier(s.identifier, s.source)
                        if s
                        else inv.bill_to_username,
                        "display_name": inv.bill_to_name,
                        "phone": s.phone if s else None,
                        "customer_name": custs.get(inv.customer_organization_id),
                        "zone_name": zones.get(zone) if zone else None,
                    }
                )
            kind = "invoices"
        return {
            "metric": metric,
            "kind": kind,
            "month": logic.month_key(month),
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, -(-total // page_size)),
        }

    # ------------------------------------------------------------ churn risk

    async def _risk_facts(
        self, isp: IspContext, b: dict[str, Any], rows: list[dict[str, Any]]
    ) -> dict[uuid.UUID, logic.RiskFacts]:
        from app.domains.guest.models import GuestSession

        from .apps_common import get_isp_apps_settings
        from .billing_models import IspInvoice, IspPayment, IspPaymentAllocation
        from .enforcement_models import IspEnforcementEvent
        from .pppoe_models import IspPppoeSession

        now, rules = b["now"], logic.RULES
        cands = [r for r in rows if r["state"] in ("active", "expired")]
        facts = {
            r["sub"].id: logic.RiskFacts(
                state=r["state"],
                valid_until=r["sub"].valid_until,
                created_at=r["sub"].created_at,
            )
            for r in cands
        }
        if not facts:
            return facts
        ids = list(facts)

        # last confirmed payment by the subscriber
        for sid, last in (
            await self.session.execute(
                select(IspPayment.subscriber_id, func.max(IspPayment.received_at))
                .where(
                    IspPayment.isp_organization_id == isp.isp_org_id,
                    IspPayment.subscriber_id.in_(ids),
                    IspPayment.status == "confirmed",
                    IspPayment.is_deleted.is_(False),
                )
                .group_by(IspPayment.subscriber_id)
            )
        ).all():
            facts[sid].last_payment_at = last

        # late: paid after the due date, or overdue now (last N days of invoices)
        since = b["today"] - timedelta(days=rules.late_lookback_days)
        last_paid = (
            select(
                IspPaymentAllocation.invoice_id.label("iid"),
                func.max(IspPayment.received_at).label("paid_at"),
            )
            .join(IspPayment, IspPayment.id == IspPaymentAllocation.payment_id)
            .where(
                IspPayment.status == "confirmed",
                IspPaymentAllocation.is_deleted.is_(False),
            )
            .group_by(IspPaymentAllocation.invoice_id)
            .subquery()
        )
        inv_rows = (
            await self.session.execute(
                select(IspInvoice, last_paid.c.paid_at)
                .outerjoin(last_paid, last_paid.c.iid == IspInvoice.id)
                .where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.subscriber_id.in_(ids),
                    IspInvoice.bill_to_kind == "subscriber",
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.status != "cancelled",
                    IspInvoice.is_deleted.is_(False),
                    IspInvoice.issue_date >= since,
                )
            )
        ).all()
        from .billing_service import balance_of

        for inv, paid_at in inv_rows:
            open_ = balance_of(inv) > 0
            late = (open_ and inv.due_date < b["today"]) or (
                not open_
                and inv.paid_paise > 0
                and paid_at is not None
                and logic.local_date(paid_at, b["tz"]) > inv.due_date
            )
            if late:
                facts[inv.subscriber_id].late_invoices += 1

        # helpdesk (JAZE-5), only while Apps is on
        if get_isp_apps_settings().enabled:
            from .apps_models import IspTicket

            for f in facts.values():
                f.open_tickets, f.recent_tickets = 0, 0
            t_since = now - timedelta(days=rules.ticket_lookback_days)
            for sid, status, opened in (
                await self.session.execute(
                    select(
                        IspTicket.subscriber_id, IspTicket.status, IspTicket.opened_at
                    ).where(
                        IspTicket.isp_organization_id == isp.isp_org_id,
                        IspTicket.subscriber_id.in_(ids),
                        IspTicket.is_deleted.is_(False),
                        or_(
                            IspTicket.status.in_(("open", "in_progress", "on_hold")),
                            IspTicket.opened_at >= t_since,
                        ),
                    )
                )
            ).all():
                if status in ("open", "in_progress", "on_hold"):
                    facts[sid].open_tickets += 1
                if opened >= t_since:
                    facts[sid].recent_tickets += 1

        # FUP throttles (JAZE-2 enforcement events)
        for sid, n, last in (
            await self.session.execute(
                select(
                    IspEnforcementEvent.subscriber_id,
                    func.count(),
                    func.max(IspEnforcementEvent.occurred_at),
                )
                .where(
                    IspEnforcementEvent.isp_organization_id == isp.isp_org_id,
                    IspEnforcementEvent.subscriber_id.in_(ids),
                    IspEnforcementEvent.kind == "fup_throttle",
                    IspEnforcementEvent.occurred_at
                    >= now - timedelta(days=rules.fup_lookback_days),
                )
                .group_by(IspEnforcementEvent.subscriber_id)
            )
        ).all():
            facts[sid].fup_hits, facts[sid].last_fup_at = int(n), last

        # last seen: hotspot sessions of the subscriber's guest at its venue,
        # PPPoE sessions of the subscriber
        by_guest = {
            (r["sub"].guest_id, r["sub"].customer_organization_id): r["sub"].id
            for r in cands
            if r["sub"].guest_id
        }
        if by_guest:
            for gid, org, last in (
                await self.session.execute(
                    select(
                        GuestSession.guest_id,
                        GuestSession.organization_id,
                        func.max(GuestSession.last_activity_at),
                    )
                    .where(
                        GuestSession.guest_id.in_({g for g, _o in by_guest}),
                        GuestSession.organization_id.in_(b["children"]),
                    )
                    .group_by(GuestSession.guest_id, GuestSession.organization_id)
                )
            ).all():
                sid = by_guest.get((gid, org))
                if sid is not None:
                    facts[sid].last_seen_at = last
        for sid, last in (
            await self.session.execute(
                select(
                    IspPppoeSession.subscriber_id,
                    func.max(
                        func.coalesce(
                            IspPppoeSession.last_update_at, IspPppoeSession.started_at
                        )
                    ),
                )
                .where(
                    IspPppoeSession.isp_organization_id == isp.isp_org_id,
                    IspPppoeSession.subscriber_id.in_(ids),
                )
                .group_by(IspPppoeSession.subscriber_id)
            )
        ).all():
            cur = facts[sid].last_seen_at
            if last is not None and (cur is None or last > cur):
                facts[sid].last_seen_at = last
        return facts

    async def _risk_rows(
        self, isp: IspContext, f: RevFilters
    ) -> tuple[dict[str, Any], list[tuple[dict, list[dict]]], bool]:
        from .apps_common import get_isp_apps_settings

        b = await self._base(isp, f)
        rows = await self._subscribers(isp, f, b)
        facts = await self._risk_facts(isp, b, rows)
        out = []
        for r in rows:
            fx = facts.get(r["sub"].id)
            if fx is None:
                continue
            reasons = logic.risk_reasons(fx, now=b["now"], tz=b["tz"])
            if reasons:
                out.append((r, reasons))
        return b, out, get_isp_apps_settings().enabled

    async def risk_summary(self, isp: IspContext, f: RevFilters) -> dict[str, Any]:
        _b, out, tickets_on = await self._risk_rows(isp, f)
        by = dict.fromkeys(logic.RISK_REASONS, 0)
        mrr = 0
        for r, reasons in out:
            mrr += r["mrr"] or 0
            for x in reasons:
                by[x["code"]] += 1
        return {
            "at_risk": len(out),
            "mrr_at_risk_paise": mrr,
            "by_reason": by,
            "tickets_measured": tickets_on,
            "weights": logic.RISK_WEIGHTS,
        }

    async def churn_risk(
        self,
        isp: IspContext,
        f: RevFilters,
        *,
        reason: str | None,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        if reason is not None and reason not in logic.RISK_REASONS:
            raise IspBadRequestError("Unknown reason", reason="ISP_QUERY_INVALID")
        _b, out, tickets_on = await self._risk_rows(isp, f)
        if reason:
            out = [(r, rs) for r, rs in out if any(x["code"] == reason for x in rs)]
        far = datetime.max.replace(tzinfo=UTC)
        out.sort(
            key=lambda x: (
                -logic.risk_score(x[1]),
                x[0]["sub"].valid_until or far,
                str(x[0]["sub"].id),
            )
        )
        total = len(out)
        chunk = out[(page - 1) * page_size : page * page_size]
        names = await self._names(
            {r["sub"].customer_organization_id for r, _rs in chunk},
            {r["sub"].package_id for r, _rs in chunk},
            {r["zone_id"] for r, _rs in chunk},
        )
        open_inv = await self._latest_open_invoice([r["sub"].id for r, _rs in chunk])
        items = []
        for r, reasons in chunk:
            item = self._sub_item(r, names)
            item["score"] = logic.risk_score(reasons)
            item["reasons"] = reasons
            item["open_invoice"] = open_inv.get(r["sub"].id)
            item["isp_customer_id"] = item["customer_id"]
            items.append(item)
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, -(-total // page_size)),
            "reason": reason,
            "tickets_measured": tickets_on,
            "rules": {
                code: {
                    "weight": logic.RISK_WEIGHTS[code],
                    "definition": logic.DEFINITIONS[code],
                }
                for code in logic.RISK_REASONS
            },
        }

    async def _latest_open_invoice(self, ids: list[uuid.UUID]) -> dict[uuid.UUID, dict]:
        """The newest open invoice per subscriber, for the pay-link share."""
        from .billing_models import IspInvoice
        from .billing_service import balance_of

        if not ids:
            return {}
        out: dict[uuid.UUID, dict] = {}
        for inv in (
            (
                await self.session.execute(
                    select(IspInvoice)
                    .where(
                        IspInvoice.subscriber_id.in_(ids),
                        IspInvoice.bill_to_kind == "subscriber",
                        IspInvoice.doc_type == "invoice",
                        IspInvoice.status.in_(OPEN_STATUSES),
                        IspInvoice.is_deleted.is_(False),
                    )
                    .order_by(
                        IspInvoice.issue_date.desc(), IspInvoice.created_at.desc()
                    )
                )
            )
            .scalars()
            .all()
        ):
            if inv.subscriber_id in out or balance_of(inv) <= 0:
                continue
            out[inv.subscriber_id] = {
                "id": str(inv.id),
                "number": inv.number,
                "total_paise": inv.total_paise,
                "balance_paise": balance_of(inv),
            }
        return out


__all__ = ["IspRevenueService", "RevFilters"]

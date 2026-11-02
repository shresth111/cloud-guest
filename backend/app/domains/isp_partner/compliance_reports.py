"""J18: the compliance/operations report catalogue.

Each report is ``(columns, rows)`` over the ISP's own tables. Reports whose
data belongs to another lane (subscriber moves, override price, deposits,
static IPs, tickets, zone ledger) are listed with ``available=False`` and a
``pending`` note until that lane's contract lands. They never return
made-up zeros.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.guest.models import GuestSession
from app.domains.ipdr.formatting import mask_email, mask_phone
from app.domains.location.models import Location
from app.domains.organization.models import Organization

from . import compliance_logic as logic
from .billing_models import IspInvoice, IspZone
from .compliance_models import IspSubscriberKyc
from .compliance_service import compliance_settings, subscriber_overlays
from .dependencies import IspContext
from .exceptions import IspBadRequestError
from .plans_models import IspPackage, IspSpeedGroup, IspSubscriber

MAX_ROWS = 50_000


#: key -> (title, category, owner lane when pending, else None)
CATALOGUE: dict[str, tuple[str, str, str | None]] = {
    "subscriber_details_status": (
        "Subscriber details with status",
        "Subscribers",
        None,
    ),
    "max_simultaneous": (
        "Simultaneous logins above the package limit",
        "Subscribers",
        None,
    ),
    "kyc_pending": ("Subscribers without complete KYC / CAF", "Compliance", None),
    "invoices_per_day": ("Invoices charged per day", "Invoicing", None),
    "invoice_zone_summary": ("Invoice summary by zone", "Invoicing", None),
    "voided_invoices": ("Cancelled invoices and credit notes", "Invoicing", None),
    "moved_subscribers": (
        "Subscribers moved across customers / zones",
        "Subscribers",
        "JAZE-1",
    ),
    "override_price": ("Subscribers on an override price", "Subscribers", "JAZE-1"),
    "security_deposits": ("Security deposits held", "Subscribers", "JAZE-4"),
    "invoice_with_static_ip": ("Invoices with static IP", "Invoicing", "JAZE-2"),
    "tickets_rfo": ("Tickets by reason for outage (RFO)", "Helpdesk", "helpdesk"),
    "tickets_tat": ("Ticket turnaround time (TAT)", "Helpdesk", "helpdesk"),
    "tickets_avg_solve": (
        "Average time to solve, by ticket type",
        "Helpdesk",
        "helpdesk",
    ),
    "zone_revenue": ("Revenue by zone (franchise breakup)", "Zones", "JAZE-4"),
    "zone_tds_194h": ("TDS (194H) on zone commissions", "Zones", "JAZE-4"),
    "zone_limit_entries": ("Zone wallet add/reduce entries", "Zones", "JAZE-4"),
}


def catalogue() -> list[dict[str, Any]]:
    return [
        {
            "key": key,
            "title": title,
            "category": category,
            "available": owner is None,
            "pending": None if owner is None else f"Data source pending ({owner})",
        }
        for key, (title, category, owner) in CATALOGUE.items()
    ]


def _rupees(paise: int | None) -> str:
    return f"{(paise or 0) / 100:.2f}"


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, date | datetime) else value


class IspComplianceReports:
    def __init__(self, session: AsyncSession, *, clock: Any = None) -> None:
        self.session = session
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(
        self,
        isp: IspContext,
        key: str,
        *,
        since: datetime,
        until: datetime,
        unmasked: bool,
    ) -> dict[str, Any]:
        if key not in CATALOGUE:
            raise IspBadRequestError(
                "Unknown report", field="key", reason="ISP_QUERY_INVALID"
            )
        title, category, owner = CATALOGUE[key]
        base = {
            "key": key,
            "title": title,
            "category": category,
            "since": since.isoformat(),
            "until": until.isoformat(),
        }
        if owner is not None:
            return {
                **base,
                "available": False,
                "pending": f"Data source pending ({owner})",
                "columns": [],
                "rows": [],
            }
        ids = await isp.child_ids()
        if not ids:
            columns, rows = getattr(self, f"_{key}")(
                [], isp, since, until, unmasked, empty=True
            )
            return {**base, "available": True, "columns": columns, "rows": []}
        columns, rows = await getattr(self, f"_{key}")(ids, isp, since, until, unmasked)
        return {
            **base,
            "available": True,
            "columns": columns,
            "rows": rows[:MAX_ROWS],
            "truncated": len(rows) > MAX_ROWS,
        }

    # -- subscribers ------------------------------------------------------
    _SUB_COLS = [
        "Circuit ID",
        "Username",
        "Customer",
        "Zone",
        "Name",
        "Phone",
        "Email",
        "Package",
        "Download Mbps",
        "Price (Rs)",
        "Status",
        "State",
        "Valid Until",
        "Created",
        "Installed",
        "Installation Address",
        "Venue",
        "Venue Latitude",
        "Venue Longitude",
        "CAF No.",
        "KYC Verified",
    ]

    def _empty(self, cols: list[str]) -> tuple[list[str], list[list[Any]]]:
        return cols, []

    def _subscriber_details_status(self, ids, isp, since, until, unmasked, empty=False):
        if empty:
            return self._empty(self._SUB_COLS)
        return self._subscriber_details_impl(ids, isp, unmasked)

    async def _subscriber_details_impl(self, ids, isp, unmasked):
        s, p, g = IspSubscriber, IspPackage, IspSpeedGroup
        rows = (
            await self.session.execute(
                select(s, p.name, p.price_paise, g.download_kbps, IspSubscriberKyc)
                .outerjoin(p, p.id == s.package_id)
                .outerjoin(g, g.id == s.speed_group_id)
                .outerjoin(
                    IspSubscriberKyc,
                    and_(
                        IspSubscriberKyc.subscriber_id == s.id,
                        IspSubscriberKyc.deleted_at.is_(None),
                    ),
                )
                .where(
                    s.isp_organization_id == isp.isp_org_id,
                    s.customer_organization_id.in_(ids),
                    s.is_deleted.is_(False),
                )
                .order_by(s.circuit_id)
            )
        ).all()
        names = await isp.repository.names(Organization, ids)
        zones = await self._zones(isp)
        venues = await self._venues(ids)
        settings = await compliance_settings(self.session, isp.isp_org_id)
        overlays = await subscriber_overlays(self.session, [r[0].id for r in rows])
        now = self._clock()
        out = []
        for sub, pkg_name, price, kbps, kyc in rows:
            venue = venues.get(sub.customer_organization_id)
            name = (
                " ".join(x for x in (sub.first_name, sub.last_name) if x)
                or sub.display_name
            )
            out.append(
                [
                    sub.circuit_id,
                    sub.identifier,
                    names.get(sub.customer_organization_id),
                    zones.get(sub.zone_id, ""),
                    (kyc.full_name if kyc and kyc.full_name else name),
                    sub.phone
                    if unmasked
                    else (mask_phone(sub.phone) if sub.phone else None),
                    sub.email
                    if unmasked
                    else (mask_email(sub.email) if sub.email else None),
                    pkg_name,
                    (kbps / 1000) if kbps else None,
                    _rupees(price) if price is not None else None,
                    sub.status,
                    logic.subscriber_state(
                        status=sub.status,
                        valid_until=sub.valid_until,
                        now=now,
                        overlay=overlays.get(sub.id),
                        churn_after=timedelta(days=settings.churn_after_days),
                    ),
                    _iso(sub.valid_until),
                    _iso(sub.created_at),
                    _iso(kyc.installed_at) if kyc else None,
                    (kyc.installation_address if kyc else None) or sub.address,
                    venue[0] if venue else None,
                    venue[1] if venue else None,
                    venue[2] if venue else None,
                    kyc.caf_number if kyc else None,
                    bool(kyc and kyc.verified_at),
                ]
            )
        return self._SUB_COLS, out

    async def _zones(self, isp) -> dict[Any, str]:
        return {
            z.id: z.name
            for z in (
                await self.session.execute(
                    select(IspZone).where(IspZone.isp_organization_id == isp.isp_org_id)
                )
            ).scalars()
        }

    async def _venues(self, ids) -> dict[uuid.UUID, tuple[str, Any, Any]]:
        """First location per customer: name + coordinates."""
        out: dict[uuid.UUID, tuple[str, Any, Any]] = {}
        for loc in (
            await self.session.execute(
                select(
                    Location.organization_id,
                    Location.name,
                    Location.latitude,
                    Location.longitude,
                )
                .where(
                    Location.organization_id.in_(ids), Location.is_deleted.is_(False)
                )
                .order_by(Location.created_at)
            )
        ).all():
            out.setdefault(loc.organization_id, (loc.name, loc.latitude, loc.longitude))
        return out

    _SIM_COLS = [
        "Circuit ID",
        "Username",
        "Customer",
        "Package",
        "Allowed Devices",
        "Peak Simultaneous Sessions",
        "Peak At",
    ]

    def _max_simultaneous(self, ids, isp, since, until, unmasked, empty=False):
        if empty:
            return self._empty(self._SIM_COLS)
        return self._max_simultaneous_impl(ids, isp, since, until)

    async def _max_simultaneous_impl(self, ids, isp, since, until):
        s, p = IspSubscriber, IspPackage
        subs = (
            await self.session.execute(
                select(
                    s.id,
                    s.circuit_id,
                    s.identifier,
                    s.guest_id,
                    s.customer_organization_id,
                    p.name,
                    p.max_devices,
                )
                .outerjoin(p, p.id == s.package_id)
                .where(
                    s.isp_organization_id == isp.isp_org_id,
                    s.customer_organization_id.in_(ids),
                    s.is_deleted.is_(False),
                    s.guest_id.is_not(None),
                )
            )
        ).all()
        by_guest = {r.guest_id: r for r in subs}
        if not by_guest:
            return self._SIM_COLS, []
        gs = GuestSession
        events: dict[uuid.UUID, list[tuple[datetime, int]]] = defaultdict(list)
        for guest_id, start, end in (
            await self.session.execute(
                select(gs.guest_id, gs.started_at, gs.ended_at).where(
                    gs.organization_id.in_(ids),
                    gs.guest_id.in_(list(by_guest)),
                    gs.started_at < until,
                    func.coalesce(gs.ended_at, until) >= since,
                )
            )
        ).all():
            events[guest_id].append((start, 1))
            events[guest_id].append((end or until, -1))
        names = await isp.repository.names(Organization, ids)
        out = []
        for guest_id, evs in events.items():
            evs.sort(key=lambda e: (e[0], e[1]))  # ends before starts at a tie
            cur = peak = 0
            peak_at = None
            for at, delta in evs:
                cur += delta
                if cur > peak:
                    peak, peak_at = cur, at
            sub = by_guest[guest_id]
            allowed = sub.max_devices or 1
            if peak > allowed:
                out.append(
                    [
                        sub.circuit_id,
                        sub.identifier,
                        names.get(sub.customer_organization_id),
                        sub.name,
                        allowed,
                        peak,
                        _iso(peak_at),
                    ]
                )
        out.sort(key=lambda r: -r[5])
        return self._SIM_COLS, out

    _KYC_COLS = [
        "Circuit ID",
        "Username",
        "Customer",
        "Has KYC",
        "ID Proof",
        "CAF No.",
        "Verified",
        "Missing",
    ]

    def _kyc_pending(self, ids, isp, since, until, unmasked, empty=False):
        if empty:
            return self._empty(self._KYC_COLS)
        return self._kyc_pending_impl(ids, isp)

    async def _kyc_pending_impl(self, ids, isp):
        s = IspSubscriber
        rows = (
            await self.session.execute(
                select(
                    s.circuit_id,
                    s.identifier,
                    s.customer_organization_id,
                    IspSubscriberKyc,
                )
                .outerjoin(
                    IspSubscriberKyc,
                    and_(
                        IspSubscriberKyc.subscriber_id == s.id,
                        IspSubscriberKyc.deleted_at.is_(None),
                    ),
                )
                .where(
                    s.isp_organization_id == isp.isp_org_id,
                    s.customer_organization_id.in_(ids),
                    s.is_deleted.is_(False),
                    s.status != "disabled",
                )
                .order_by(s.circuit_id)
            )
        ).all()
        names = await isp.repository.names(Organization, ids)
        out = []
        for circuit, ident, cust, kyc in rows:
            missing = []
            if kyc is None:
                missing.append("KYC record")
            else:
                if not kyc.id_proof_type or not kyc.id_number_last4:
                    missing.append("ID proof")
                if not kyc.installation_address:
                    missing.append("installation address")
                if not kyc.caf_number:
                    missing.append("CAF number")
                if not kyc.verified_at:
                    missing.append("verification")
            if missing:
                out.append(
                    [
                        circuit,
                        ident,
                        names.get(cust),
                        kyc is not None,
                        kyc.id_proof_type if kyc else None,
                        kyc.caf_number if kyc else None,
                        bool(kyc and kyc.verified_at),
                        ", ".join(missing),
                    ]
                )
        return self._KYC_COLS, out

    # -- invoicing --------------------------------------------------------
    def _inv_where(self, isp, ids, since, until):
        inv = IspInvoice
        confined = isp.confined_customer_ids is not None
        conds = [
            inv.isp_organization_id == isp.isp_org_id,
            inv.issue_date >= since.date(),
            inv.issue_date <= until.date(),
            inv.is_deleted.is_(False),
        ]
        if confined:
            conds.append(inv.customer_organization_id.in_(ids))
        return conds

    _DAY_COLS = [
        "Date",
        "Invoices",
        "Credit Notes",
        "Taxable (Rs)",
        "CGST (Rs)",
        "SGST (Rs)",
        "IGST (Rs)",
        "Total (Rs)",
    ]

    def _invoices_per_day(self, ids, isp, since, until, unmasked, empty=False):
        if empty:
            return self._empty(self._DAY_COLS)
        return self._invoices_per_day_impl(ids, isp, since, until)

    async def _invoices_per_day_impl(self, ids, isp, since, until):
        inv = IspInvoice
        rows = (
            await self.session.execute(
                select(
                    inv.issue_date,
                    inv.doc_type,
                    func.count(),
                    func.sum(inv.taxable_paise),
                    func.sum(inv.cgst_paise),
                    func.sum(inv.sgst_paise),
                    func.sum(inv.igst_paise),
                    func.sum(inv.total_paise),
                )
                .where(
                    *self._inv_where(isp, ids, since, until), inv.status != "cancelled"
                )
                .group_by(inv.issue_date, inv.doc_type)
                .order_by(inv.issue_date)
            )
        ).all()
        days: dict[date, list[int]] = {}
        for day, doc_type, n, tax, cg, sg, ig, tot in rows:
            acc = days.setdefault(day, [0, 0, 0, 0, 0, 0, 0])
            sign = -1 if doc_type == "credit_note" else 1
            acc[0 if sign == 1 else 1] += n
            for i, v in enumerate((tax, cg, sg, ig, tot), start=2):
                acc[i] += sign * int(v or 0)
        return self._DAY_COLS, [
            [d.isoformat(), a[0], a[1], *(_rupees(x) for x in a[2:])]
            for d, a in sorted(days.items())
        ]

    _ZONE_COLS = [
        "Zone",
        "Invoices",
        "Taxable (Rs)",
        "GST (Rs)",
        "Total (Rs)",
        "Paid (Rs)",
        "Balance (Rs)",
    ]

    def _invoice_zone_summary(self, ids, isp, since, until, unmasked, empty=False):
        if empty:
            return self._empty(self._ZONE_COLS)
        return self._invoice_zone_summary_impl(ids, isp, since, until)

    async def _invoice_zone_summary_impl(self, ids, isp, since, until):
        inv = IspInvoice
        rows = (
            await self.session.execute(
                select(
                    inv.zone_id,
                    func.count(),
                    func.sum(inv.taxable_paise),
                    func.sum(inv.cgst_paise + inv.sgst_paise + inv.igst_paise),
                    func.sum(inv.total_paise),
                    func.sum(inv.paid_paise),
                    func.sum(inv.credit_noted_paise),
                )
                .where(
                    *self._inv_where(isp, ids, since, until),
                    inv.status != "cancelled",
                    inv.doc_type == "invoice",
                )
                .group_by(inv.zone_id)
            )
        ).all()
        zones = await self._zones(isp)
        out = []
        for zone_id, n, tax, gst, tot, paid, cn in rows:
            balance = int(tot or 0) - int(paid or 0) - int(cn or 0)
            out.append(
                [
                    zones.get(zone_id, "No zone") if zone_id else "No zone",
                    n,
                    _rupees(tax),
                    _rupees(gst),
                    _rupees(tot),
                    _rupees(paid),
                    _rupees(balance),
                ]
            )
        out.sort(key=lambda r: r[0])
        return self._ZONE_COLS, out

    _VOID_COLS = [
        "Number",
        "Type",
        "Issue Date",
        "Bill To",
        "Total (Rs)",
        "Status",
        "Reason",
        "Credit Note For",
        "Last Changed",
    ]

    def _voided_invoices(self, ids, isp, since, until, unmasked, empty=False):
        if empty:
            return self._empty(self._VOID_COLS)
        return self._voided_invoices_impl(ids, isp, since, until)

    async def _voided_invoices_impl(self, ids, isp, since, until):
        inv = IspInvoice
        rows = (
            (
                await self.session.execute(
                    select(inv)
                    .where(
                        *self._inv_where(isp, ids, since, until),
                        (inv.status == "cancelled") | (inv.doc_type == "credit_note"),
                    )
                    .order_by(inv.issue_date, inv.number)
                )
            )
            .scalars()
            .all()
        )
        numbers = {}
        refs = {
            r.credit_note_for_invoice_id for r in rows if r.credit_note_for_invoice_id
        }
        if refs:
            numbers = dict(
                (
                    await self.session.execute(
                        select(inv.id, inv.number).where(inv.id.in_(refs))
                    )
                ).all()
            )
        return self._VOID_COLS, [
            [
                r.number,
                r.doc_type,
                r.issue_date.isoformat(),
                r.bill_to_name,
                _rupees(r.total_paise),
                r.status,
                r.cancelled_reason,
                numbers.get(r.credit_note_for_invoice_id),
                _iso(r.updated_at),
            ]
            for r in rows
        ]

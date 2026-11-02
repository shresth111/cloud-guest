"""JAZE-3 compliance reads: dashboard counters, NAT-feed health, CGNAT
lookup, session dump, TRAI PMR pack, AGR (ADDENDUM_05 J4/J5/J12/J17).

Every query runs over an explicit customer id list taken from
``IspContext.child_ids()`` (confinement already applied). An empty list
returns empty results without querying -- never platform totals
(see [[wyfy-global-scope-unscopes-reports]]).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.models import Guest, GuestDevice, GuestSession
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import is_controller_managed_row
from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord
from app.domains.traffic_flow.models import RouterTrafficFlowExport

from . import compliance_logic as logic
from .billing_models import IspCustomerBilling, IspInvoice, IspInvoiceLine, IspZone
from .compliance_models import IspComplianceSettings, IspSubscriberKyc
from .dependencies import IspContext
from .exceptions import IspBadRequestError
from .plans_models import IspSpeedGroup, IspSubscriber
from .scoping import IspScope

logger = get_logger(__name__)

#: How far back the NAT-feed query looks. Older = "never" in this view; the
#: index on (router_id, window_start) keeps it to a range scan.
NAT_FEED_LOOKBACK = timedelta(hours=48)
SESSION_DUMP_MAX_DAYS = 31
SESSION_DUMP_MAX_ROWS = 200_000


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def compliance_settings(
    session: AsyncSession, isp_org_id: uuid.UUID
) -> IspComplianceSettings:
    """The ISP's row, or an unsaved one with the defaults (reads never
    create rows)."""
    row = (
        await session.execute(
            select(IspComplianceSettings).where(
                IspComplianceSettings.isp_organization_id == isp_org_id,
                IspComplianceSettings.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is not None:
        return row
    return IspComplianceSettings(
        isp_organization_id=isp_org_id,
        caf_prefix="CAF",
        caf_next_seq=1,
        nat_feed_stale_minutes=60,
        gigabit_threshold_mbps=1000,
        churn_after_days=60,
    )


async def subscriber_overlays(
    session: AsyncSession, subscriber_ids: list[uuid.UUID]
) -> dict[uuid.UUID, str]:
    """Lifecycle overlays (suspended / frozen / blocked) recorded by JAZE-1.

    JAZE-1 owns that table; until its contract is merged this returns {} and
    the counters derive state from ``isp_subscribers`` alone. The import is
    looked up lazily so this module never depends on JAZE-1's file."""
    if not subscriber_ids:
        return {}
    try:
        from . import subscriber_lifecycle  # type: ignore[attr-defined]
    except ImportError:
        return {}
    reader = getattr(subscriber_lifecycle, "overlay_states", None)
    if reader is None:
        return {}
    return await reader(session, subscriber_ids)


class IspComplianceService:
    def __init__(self, session: AsyncSession, *, clock: Any = None) -> None:
        self.session = session
        self._clock = clock or (lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return _aware(self._clock())

    async def _customer_ids(
        self, isp: IspContext, isp_customer_id: uuid.UUID | None
    ) -> list[uuid.UUID]:
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            return [isp_customer_id]
        return await isp.child_ids()

    # ------------------------------------------------------------------
    # J4: counters
    # ------------------------------------------------------------------
    async def counters(
        self, isp: IspContext, *, isp_customer_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        now = self.now()
        ids = await self._customer_ids(isp, isp_customer_id)
        settings = await compliance_settings(self.session, isp.isp_org_id)
        churn_after = timedelta(days=settings.churn_after_days)
        if not ids:
            return {
                "counters": dict.fromkeys(logic.COUNTER_KEYS, 0),
                "online_sessions": 0,
                "definitions": _COUNTER_DEFINITIONS,
                "overlay_source": "pending",
                "as_of": now.isoformat(),
            }
        s = IspSubscriber
        rows = (
            await self.session.execute(
                select(s.id, s.status, s.valid_until, s.created_at, s.guest_id).where(
                    s.isp_organization_id == isp.isp_org_id,
                    s.customer_organization_id.in_(ids),
                    s.is_deleted.is_(False),
                )
            )
        ).all()
        overlays = await subscriber_overlays(self.session, [r.id for r in rows])
        guest_to_sub = {r.guest_id: r.id for r in rows if r.guest_id is not None}
        online_guest_ids: set[uuid.UUID] = set()
        online_sessions = 0
        if ids:
            active = (
                (
                    await self.session.execute(
                        select(GuestSession.guest_id).where(
                            GuestSession.organization_id.in_(ids),
                            GuestSession.status == GuestSessionStatus.ACTIVE.value,
                        )
                    )
                )
                .scalars()
                .all()
            )
            online_sessions = len(active)
            online_guest_ids = set(active)
        online_ids = {guest_to_sub[g] for g in online_guest_ids if g in guest_to_sub}
        counts = logic.count_states(
            (
                {
                    "id": r.id,
                    "status": r.status,
                    "valid_until": r.valid_until,
                    "created_at": r.created_at,
                    "overlay": overlays.get(r.id),
                }
                for r in rows
            ),
            now=now,
            online_ids=online_ids,
            renewal_ids=set(),
            churn_after=churn_after,
        )
        horizon = (now + timedelta(days=7)).date()
        counts["scheduled_renewals"] = int(
            (
                await self.session.execute(
                    select(func.count()).where(
                        IspCustomerBilling.customer_organization_id.in_(ids),
                        IspCustomerBilling.active.is_(True),
                        IspCustomerBilling.next_invoice_date <= horizon,
                        IspCustomerBilling.is_deleted.is_(False),
                    )
                )
            ).scalar_one()
            or 0
        )
        return {
            "counters": counts,
            "online_sessions": online_sessions,
            "definitions": _COUNTER_DEFINITIONS,
            "overlay_source": "jaze1" if overlays else "derived",
            "as_of": now.isoformat(),
        }

    # ------------------------------------------------------------------
    # J4: NAT feed per router
    # ------------------------------------------------------------------
    async def nat_feed(
        self, isp: IspContext, *, isp_customer_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        now = self.now()
        ids = await self._customer_ids(isp, isp_customer_id)
        settings = await compliance_settings(self.session, isp.isp_org_id)
        stale_after = timedelta(minutes=settings.nat_feed_stale_minutes)
        if not ids:
            return _feed_payload([], now, stale_after)
        # Whole rows (CI-INTEG): is_controller_managed_row needs the vendor
        # and the agent-evidence columns, not only the label.
        routers = (
            (
                await self.session.execute(
                    select(Router).where(
                        Router.organization_id.in_(ids),
                        Router.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        router_ids = [r.id for r in routers]
        last_nat: dict[uuid.UUID, datetime] = {}
        last_flow: dict[uuid.UUID, datetime] = {}
        exports: dict[uuid.UUID, Any] = {}
        if router_ids:
            since = now - NAT_FEED_LOOKBACK
            f = TrafficFlowRecord
            base = and_(f.router_id.in_(router_ids), f.window_start >= since)
            for rid, at in (
                await self.session.execute(
                    select(f.router_id, func.max(f.window_start))
                    .where(base, f.nat_src_address.is_not(None))
                    .group_by(f.router_id)
                )
            ).all():
                last_nat[rid] = at
            for rid, at in (
                await self.session.execute(
                    select(f.router_id, func.max(f.window_start))
                    .where(base)
                    .group_by(f.router_id)
                )
            ).all():
                last_flow[rid] = at
            for row in (
                await self.session.execute(
                    select(RouterTrafficFlowExport).where(
                        RouterTrafficFlowExport.router_id.in_(router_ids),
                        RouterTrafficFlowExport.is_deleted.is_(False),
                    )
                )
            ).scalars():
                exports[row.router_id] = row
        names = await isp.repository.names(Organization, ids)
        loc_ids = list({r.location_id for r in routers})
        loc_names = await isp.repository.names(Location, loc_ids) if loc_ids else {}
        items = []
        for r in routers:
            export = exports.get(r.id)
            configured = bool(export and export.enabled)
            state = logic.nat_feed_state(
                last_nat_at=last_nat.get(r.id),
                export_configured=configured,
                router_online=r.status == RouterStatus.ONLINE.value,
                now=now,
                stale_after=stale_after,
                controller_managed=is_controller_managed_row(r),
            )
            items.append(
                {
                    "isp_router_id": str(r.id),
                    "router_name": r.name,
                    "isp_customer_id": str(r.organization_id),
                    "customer_name": names.get(r.organization_id),
                    "isp_location_id": str(r.location_id),
                    "location_name": loc_names.get(r.location_id),
                    "router_status": r.status,
                    "public_ip": r.public_ip_address,
                    "state": state,
                    "alerting": state in logic.FEED_ALERTING,
                    "last_nat_record_at": _iso(last_nat.get(r.id)),
                    "last_flow_record_at": _iso(last_flow.get(r.id)),
                    "export_configured": configured,
                    "export_last_verified_at": _iso(
                        export.last_verified_at if export else None
                    ),
                    "export_last_verdict_ok": export.last_verdict_ok
                    if export
                    else None,
                    "export_last_verdict_detail": (
                        export.last_verdict_detail if export else None
                    ),
                    "ipdr_ports": bool(export.ipdr_ports) if export else False,
                }
            )
        items.sort(
            key=lambda i: (
                not i["alerting"],
                i["customer_name"] or "",
                i["router_name"],
            )
        )
        return _feed_payload(items, now, stale_after)

    # ------------------------------------------------------------------
    # J5: CGNAT lookup
    # ------------------------------------------------------------------
    async def had_nat_data(
        self, router_ids: list[uuid.UUID], since: datetime, until: datetime
    ) -> bool:
        if not router_ids:
            return False
        f = TrafficFlowRecord
        found = (
            await self.session.execute(
                select(f.id)
                .where(
                    f.router_id.in_(router_ids),
                    f.window_start >= since - timedelta(minutes=10),
                    f.window_start < until,
                    f.nat_src_address.is_not(None),
                )
                .limit(1)
            )
        ).first()
        return found is not None

    async def routers_of(self, customer_ids: list[uuid.UUID]) -> list[Any]:
        if not customer_ids:
            return []
        return list(
            (
                await self.session.execute(
                    select(
                        Router.id,
                        Router.name,
                        Router.organization_id,
                        Router.location_id,
                        Router.public_ip_address,
                    ).where(
                        Router.organization_id.in_(customer_ids),
                        Router.is_deleted.is_(False),
                    )
                )
            ).all()
        )

    async def subscriber_dossiers(
        self, isp: IspContext, keys: set[tuple[str, str]]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """(customer org id, identifier) -> the subscriber + KYC summary."""
        if not keys:
            return {}
        orgs = {uuid.UUID(k[0]) for k in keys}
        idents = {k[1] for k in keys}
        s = IspSubscriber
        rows = (
            await self.session.execute(
                select(s, IspSubscriberKyc)
                .outerjoin(
                    IspSubscriberKyc,
                    and_(
                        IspSubscriberKyc.subscriber_id == s.id,
                        IspSubscriberKyc.deleted_at.is_(None),
                    ),
                )
                .where(
                    s.isp_organization_id == isp.isp_org_id,
                    s.customer_organization_id.in_(orgs),
                    func.lower(s.identifier).in_({i.lower() for i in idents}),
                    s.is_deleted.is_(False),
                )
            )
        ).all()
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for sub, kyc in rows:
            key = (str(sub.customer_organization_id), sub.identifier.lower())
            out[key] = dossier_view(sub, kyc)
        return out

    # ------------------------------------------------------------------
    # J12: session dump
    # ------------------------------------------------------------------
    async def session_rows(
        self,
        isp: IspContext,
        *,
        since: datetime,
        until: datetime,
        isp_customer_id: uuid.UUID | None,
        max_rows: int = SESSION_DUMP_MAX_ROWS,
    ) -> AsyncIterator[dict[str, Any]]:
        ids = await self._customer_ids(isp, isp_customer_id)
        if not ids:
            return
        names = await isp.repository.names(Organization, ids)
        zones = {
            z.id: z.name
            for z in (
                await self.session.execute(
                    select(IspZone).where(IspZone.isp_organization_id == isp.isp_org_id)
                )
            ).scalars()
        }
        gs = GuestSession
        statement = (
            select(
                gs,
                Guest,
                GuestDevice.mac_address,
                Router.name,
                Location.name,
                IspSubscriber,
                IspSubscriberKyc,
            )
            .join(Guest, Guest.id == gs.guest_id)
            .outerjoin(GuestDevice, GuestDevice.id == gs.device_id)
            .outerjoin(Router, Router.id == gs.router_id)
            .outerjoin(Location, Location.id == gs.location_id)
            .outerjoin(
                IspSubscriber,
                and_(
                    IspSubscriber.guest_id == gs.guest_id,
                    IspSubscriber.customer_organization_id == gs.organization_id,
                    IspSubscriber.is_deleted.is_(False),
                ),
            )
            .outerjoin(
                IspSubscriberKyc,
                and_(
                    IspSubscriberKyc.subscriber_id == IspSubscriber.id,
                    IspSubscriberKyc.deleted_at.is_(None),
                ),
            )
            .where(
                gs.organization_id.in_(ids),
                gs.started_at < until,
                func.coalesce(gs.ended_at, until) >= since,
            )
            .order_by(gs.started_at)
            .limit(max_rows + 1)
            .execution_options(yield_per=2000)
        )
        written = 0
        result = await self.session.stream(statement)
        async for sess, guest, mac, router_name, location_name, sub, kyc in result:
            if written >= max_rows:
                yield {"__truncated__": max_rows}
                return
            written += 1
            yield session_dump_row(
                sess,
                guest,
                mac=mac,
                router_name=router_name,
                location_name=location_name,
                customer_name=names.get(sess.organization_id),
                subscriber=sub,
                kyc=kyc,
                zone_name=zones.get(sub.zone_id)
                if sub is not None and sub.zone_id
                else None,
            )

    # ------------------------------------------------------------------
    # J17: TRAI PMR
    # ------------------------------------------------------------------
    async def trai_pmr(self, isp: IspContext, *, period: str) -> dict[str, Any]:
        try:
            start, end = logic.month_bounds(period)
        except ValueError as exc:
            raise IspBadRequestError(str(exc), field="period") from exc
        ids = await isp.child_ids()
        settings = await compliance_settings(self.session, isp.isp_org_id)
        threshold_kbps = settings.gigabit_threshold_mbps * 1000
        tiers = {label: 0 for label, _, _ in logic.SPEED_TIERS}
        tiers[logic.TIER_UNKNOWN] = 0
        gigabit: list[dict[str, Any]] = []
        hotspot = {
            "venues": 0,
            "nas_routers": 0,
            "access_points": None,
            "access_points_note": (
                "Access points are not tracked per venue on this platform; "
                "the NAS (router) count is given instead."
            ),
            "registered_users": 0,
            "users_active_in_period": 0,
            "sessions_in_period": 0,
            "download_bytes": 0,
            "upload_bytes": 0,
        }
        usage = {"download_bytes": 0, "upload_bytes": 0}
        if ids:
            s = IspSubscriber
            g = IspSpeedGroup
            subs = (
                await self.session.execute(
                    select(
                        s.id,
                        s.identifier,
                        s.circuit_id,
                        s.customer_organization_id,
                        s.status,
                        s.valid_until,
                        s.created_at,
                        g.download_kbps,
                    )
                    .outerjoin(g, g.id == s.speed_group_id)
                    .where(
                        s.isp_organization_id == isp.isp_org_id,
                        s.customer_organization_id.in_(ids),
                        s.is_deleted.is_(False),
                        s.created_at < end,
                    )
                )
            ).all()
            names = await isp.repository.names(Organization, ids)
            for row in subs:
                # counted when it existed by the month's end, was valid at some
                # point in the month (or is open-ended) and is not disabled
                if row.status == "disabled":
                    continue
                if row.valid_until is not None and row.valid_until < start:
                    continue
                tiers[logic.speed_tier(row.download_kbps)] += 1
                if row.download_kbps and row.download_kbps >= threshold_kbps:
                    gigabit.append(
                        {
                            "circuit_id": row.circuit_id,
                            "username": row.identifier,
                            "customer_name": names.get(row.customer_organization_id),
                            "download_mbps": row.download_kbps / 1000,
                        }
                    )
            loc = Location
            hotspot["venues"] = int(
                (
                    await self.session.execute(
                        select(func.count()).where(
                            loc.organization_id.in_(ids),
                            loc.is_deleted.is_(False),
                            loc.created_at < end,
                        )
                    )
                ).scalar_one()
                or 0
            )
            hotspot["nas_routers"] = int(
                (
                    await self.session.execute(
                        select(func.count()).where(
                            Router.organization_id.in_(ids),
                            Router.is_deleted.is_(False),
                            Router.created_at < end,
                        )
                    )
                ).scalar_one()
                or 0
            )
            hotspot["registered_users"] = int(
                (
                    await self.session.execute(
                        select(func.count()).where(
                            Guest.organization_id.in_(ids), Guest.created_at < end
                        )
                    )
                ).scalar_one()
                or 0
            )
            gs = GuestSession
            agg = (
                await self.session.execute(
                    select(
                        func.count(),
                        func.count(func.distinct(gs.guest_id)),
                        func.coalesce(func.sum(gs.bytes_downloaded), 0),
                        func.coalesce(func.sum(gs.bytes_uploaded), 0),
                    ).where(
                        gs.organization_id.in_(ids),
                        gs.started_at >= start,
                        gs.started_at < end,
                    )
                )
            ).one()
            hotspot["sessions_in_period"] = int(agg[0] or 0)
            hotspot["users_active_in_period"] = int(agg[1] or 0)
            hotspot["download_bytes"] = int(agg[2] or 0)
            hotspot["upload_bytes"] = int(agg[3] or 0)
            usage["download_bytes"] = hotspot["download_bytes"]
            usage["upload_bytes"] = hotspot["upload_bytes"]
        tb = 1000**4
        return {
            "period": period,
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "timezone": "Asia/Kolkata",
            "subscriptions_by_speed": [
                {"tier": label, "subscribers": count} for label, count in tiers.items()
            ],
            "subscriptions_total": sum(tiers.values()),
            "gigabit_threshold_mbps": settings.gigabit_threshold_mbps,
            "gigabit_subscribers": gigabit,
            "public_wifi_hotspots": hotspot,
            "data_usage": {
                **usage,
                "download_tb": round(usage["download_bytes"] / tb, 6),
                "upload_tb": round(usage["upload_bytes"] / tb, 6),
                "source": (
                    "Guest session byte counters (RADIUS accounting) across the "
                    "ISP's customers; sessions are attributed to the month they "
                    "started in."
                ),
            },
            "notes": [
                "Subscriber counts come from Wyfy subscribers (hotspot coupon "
                "and manual). Speed is the subscriber's speed group download rate.",
                "Check every figure against your own records before filing; "
                "Wyfy prepares the data, the licensee files it.",
            ],
        }

    # ------------------------------------------------------------------
    # J17: AGR
    # ------------------------------------------------------------------
    async def agr(self, isp: IspContext, *, since: date, until: date) -> dict[str, Any]:
        if since > until:
            raise IspBadRequestError(
                "since must not be after until",
                field="since",
                reason="ISP_DATE_RANGE_ORDER",
            )
        if (until - since).days > 400:
            raise IspBadRequestError(
                "range is limited to 400 days",
                field="until",
                reason="ISP_DATE_RANGE_TOO_LONG",
                max_days=400,
            )
        inv, line = IspInvoice, IspInvoiceLine
        rows = (
            await self.session.execute(
                select(
                    inv.doc_type,
                    inv.status,
                    line.sac_code,
                    line.taxable_paise,
                    line.cgst_paise,
                    line.sgst_paise,
                    line.igst_paise,
                    inv.issue_date,
                )
                .join(line, line.invoice_id == inv.id)
                .where(
                    inv.isp_organization_id == isp.isp_org_id,
                    inv.issue_date >= since,
                    inv.issue_date <= until,
                    inv.status != "cancelled",
                    inv.is_deleted.is_(False),
                )
            )
        ).all()
        confined = isp.confined_customer_ids is not None
        lines = [
            {
                "sac_code": r.sac_code,
                "taxable_paise": r.taxable_paise,
                "sign": -1 if r.doc_type == "credit_note" else 1,
            }
            for r in rows
        ]
        split = logic.agr_split(lines)
        by_sac: dict[str, int] = {}
        gst = 0
        for r in rows:
            sign = -1 if r.doc_type == "credit_note" else 1
            by_sac[r.sac_code] = by_sac.get(r.sac_code, 0) + sign * r.taxable_paise
            gst += sign * (r.cgst_paise + r.sgst_paise + r.igst_paise)
        return {
            "since": since.isoformat(),
            "until": until.isoformat(),
            **split,
            "gst_collected_paise": gst,
            "by_sac": [
                {"sac_code": k, "taxable_paise": v} for k, v in sorted(by_sac.items())
            ],
            "invoice_lines": len(rows),
            "partial_view": confined,
            "notes": [
                "Telecom revenue = taxable value of lines with SAC under 9984. "
                "GST is excluded. Credit notes are subtracted. Cancelled "
                "invoices are excluded.",
                "Only invoices raised in Wyfy are included. Add revenue billed "
                "elsewhere before computing the licence fee.",
            ],
        }


_COUNTER_DEFINITIONS = {
    "online": "Subscribers with an active Wi-Fi session now.",
    "active": "Valid now: not expired, not blocked, frozen or suspended.",
    "expiring_7d": "Active subscribers whose validity ends within 7 days.",
    "expired": "Validity ended, within the churn window.",
    "suspended": "Suspended for dues (from the subscriber lifecycle).",
    "frozen": "Validity paused at the customer's request.",
    "blocked": "Turned off by the ISP (disabled or blocked).",
    "churned": "Expired for longer than the churn window (default 60 days).",
    "new_7d": "Subscribers created in the last 7 days.",
    "scheduled_renewals": "Customer billing cycles due within 7 days.",
    "total": "All subscribers (each counted once, in one state).",
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _feed_payload(
    items: list[dict[str, Any]], now: datetime, stale_after: timedelta
) -> dict[str, Any]:
    alerting = [i for i in items if i["alerting"]]
    return {
        "as_of": now.isoformat(),
        "stale_after_minutes": int(stale_after.total_seconds() // 60),
        "routers": items,
        "alerting_count": len(alerting),
        "banner": bool(alerting),
        "source": (
            "NAT translations arrive as IPFIX flow/NAT-event records from each "
            "router (Traffic Lens). A router that exports flows without NAT "
            "fields counts as not receiving NAT logs."
        ),
    }


def dossier_view(sub: Any, kyc: Any) -> dict[str, Any]:
    name = " ".join(p for p in (sub.first_name, sub.last_name) if p) or sub.display_name
    return {
        "subscriber_id": str(sub.id),
        "circuit_id": sub.circuit_id,
        "username": sub.identifier,
        "name": (kyc.full_name if kyc and kyc.full_name else None) or name,
        "phone": sub.phone,
        "email": sub.email,
        "address": ((kyc.installation_address if kyc else None) or sub.address),
        "status": sub.status,
        "valid_until": _iso(sub.valid_until),
        "caf_number": kyc.caf_number if kyc else None,
        "id_proof_type": kyc.id_proof_type if kyc else None,
        "id_number_masked": kyc.id_number_masked if kyc else None,
        "kyc_on_file": kyc is not None,
    }


def _device(user_agent: str | None) -> tuple[str, str]:
    ua = (user_agent or "").lower()
    if not ua:
        return "", ""
    device = (
        "Tablet"
        if "ipad" in ua or "tablet" in ua
        else "Mobile"
        if "mobi" in ua or "android" in ua or "iphone" in ua
        else "Desktop"
    )
    for token, name in (
        ("edg/", "Edge"),
        ("opr/", "Opera"),
        ("samsungbrowser", "Samsung Internet"),
        ("chrome/", "Chrome"),
        ("firefox/", "Firefox"),
        ("safari/", "Safari"),
    ):
        if token in ua:
            return device, name
    return device, "Other"


def session_dump_row(
    sess: Any,
    guest: Any,
    *,
    mac: str | None,
    router_name: str | None,
    location_name: str | None,
    customer_name: str | None,
    subscriber: Any,
    kyc: Any,
    zone_name: str | None,
) -> dict[str, Any]:
    device, browser = _device(getattr(sess, "user_agent", None))
    end = sess.ended_at
    seconds = (
        int((end - sess.started_at).total_seconds())
        if end is not None and sess.started_at is not None
        else None
    )
    name = None
    phone = None
    email = getattr(guest, "email", None)
    address = None
    if subscriber is not None:
        name = (
            " ".join(p for p in (subscriber.first_name, subscriber.last_name) if p)
            or subscriber.display_name
        )
        phone = subscriber.phone
        email = subscriber.email or email
        address = subscriber.address
    if kyc is not None:
        name = kyc.full_name or name
        address = kyc.installation_address or address
    identifier = getattr(guest, "identifier", None)
    if phone is None and identifier and identifier.lstrip("+").isdigit():
        phone = identifier
    return {
        "Session Start (IST)": sess.started_at,
        "Session End (IST)": end,
        "Duration (s)": seconds,
        "Username": identifier,
        "Subscriber ID": subscriber.circuit_id if subscriber is not None else "",
        "Customer": customer_name,
        "Zone": zone_name or "",
        "Location": location_name,
        "Name": name or getattr(guest, "display_name", None),
        "Phone": phone,
        "Email": email,
        "Address": address,
        "Gender": kyc.gender if kyc is not None else "",
        "CAF No.": kyc.caf_number if kyc is not None else "",
        "Login Type": sess.auth_method,
        "MAC": mac,
        "IP Address": sess.ip_address,
        "IPv6 Prefix": "",
        "Device Type": device,
        "Browser": browser,
        "AP MAC": "",
        "AP Name": "",
        "NAS": router_name,
        "NAS Port": "",
        "Bytes Up": int(getattr(sess, "bytes_uploaded", 0) or 0),
        "Bytes Down": int(getattr(sess, "bytes_downloaded", 0) or 0),
        "Status": sess.status,
    }


SESSION_DUMP_COLUMNS: tuple[str, ...] = (
    "Session Start (IST)",
    "Session End (IST)",
    "Duration (s)",
    "Username",
    "Subscriber ID",
    "Customer",
    "Zone",
    "Location",
    "Name",
    "Phone",
    "Email",
    "Address",
    "Gender",
    "CAF No.",
    "Login Type",
    "MAC",
    "IP Address",
    "IPv6 Prefix",
    "Device Type",
    "Browser",
    "AP MAC",
    "AP Name",
    "NAS",
    "NAS Port",
    "Bytes Up",
    "Bytes Down",
    "Status",
)
#: Columns the platform does not capture today: always empty, listed in the
#: export's header note so nobody reads an empty cell as "none".
SESSION_DUMP_NOT_CAPTURED = ("IPv6 Prefix", "AP MAC", "AP Name", "NAS Port")

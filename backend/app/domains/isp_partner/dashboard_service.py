"""DASH-1: subscriber operations dashboard (rules in ``dashboard_logic``).

One pass builds a row per subscriber in view (bucket + overlays); the tiles
and the drill-down list are both computed from those same rows, so a list's
``total`` is always the tile's number.

In view = the ISP's subscribers under the caller's customers
(``isp.child_ids()``, already narrowed by the ZONE-1 ``scope_zone_id``; the
ORM selects of ``isp_subscribers`` also carry ZONE-1's zone criterion), then
the optional filters: package, connection type (JAZE-1 profile) and router
(subscribers with any hotspot or PPPoE session on that router).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from types import SimpleNamespace
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select

from . import dashboard_logic as logic
from .dependencies import IspContext
from .exceptions import IspBadRequestError
from .scoping import IspScope

PERIODS = ("today", "7d", "30d", "custom")


@dataclass(frozen=True)
class Filters:
    period: str = "7d"
    date_from: date | None = None
    date_to: date | None = None
    router_id: uuid.UUID | None = None
    package_id: uuid.UUID | None = None
    connection_type: str | None = None


def period_bounds(
    f: Filters, *, now: datetime, tz: str
) -> tuple[date, date, datetime, datetime]:
    """(from, to, start, end): plain dates in the ISP's time zone, ``to``
    inclusive; ``start``/``end`` the matching UTC instants (end exclusive)."""
    zone = ZoneInfo(tz or "Asia/Kolkata")
    today = now.astimezone(zone).date()
    if f.period == "today":
        d0 = d1 = today
    elif f.period == "7d":
        d0, d1 = today - timedelta(days=6), today
    elif f.period == "30d":
        d0, d1 = today - timedelta(days=29), today
    elif f.period == "custom":
        if f.date_from is None or f.date_to is None:
            raise IspBadRequestError("A custom period needs date_from and date_to")
        d0, d1 = f.date_from, f.date_to
    else:
        raise IspBadRequestError("period is today, 7d, 30d or custom")
    if d1 < d0 or (d1 - d0).days > 400:
        raise IspBadRequestError("The period must be 1 to 401 days, start before end")
    start = datetime.combine(d0, time.min, tzinfo=zone).astimezone(UTC)
    end = datetime.combine(d1 + timedelta(days=1), time.min, tzinfo=zone).astimezone(
        UTC
    )
    return d0, d1, start, end


class IspDashboardService:
    def __init__(self, session: Any, *, clock: Any = None) -> None:
        self.session = session
        self._clock = clock or (lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return self._clock()

    async def _rows(self, isp: IspContext, f: Filters) -> dict[str, Any]:
        from app.domains.guest.constants import GuestSessionStatus
        from app.domains.guest.models import GuestSession

        from .compliance_models import IspSubscriberKyc
        from .compliance_service import compliance_settings
        from .plans_models import IspPackage, IspSubscriber
        from .pppoe_config import get_isp_pppoe_settings
        from .subscriber360_models import IspSubscriberProfile
        from .subscriber360_service import IspSubscriber360Service

        now = self.now()
        d0, d1, start, end = period_bounds(
            f, now=now, tz=getattr(isp.organization, "timezone", None) or "Asia/Kolkata"
        )
        pppoe_on = get_isp_pppoe_settings().enabled
        children = await isp.child_ids()
        base = {
            "now": now,
            "period": {
                "period": f.period,
                "date_from": d0.isoformat(),
                "date_to": d1.isoformat(),
            },
            "pppoe_enabled": pppoe_on,
            "children": children,
            "rows": [],
            "sessions": {"hotspot": 0, "pppoe": 0},
        }
        router = None
        if f.router_id is not None:
            router = await IspScope.assert_router(isp, f.router_id)  # 404 outside scope
        if not children:
            return base

        q = (
            select(IspSubscriber, IspSubscriberProfile, IspPackage.type)
            .outerjoin(
                IspSubscriberProfile,
                (IspSubscriberProfile.subscriber_id == IspSubscriber.id)
                & IspSubscriberProfile.is_deleted.is_(False),
            )
            .outerjoin(IspPackage, IspPackage.id == IspSubscriber.package_id)
            .where(
                IspSubscriber.isp_organization_id == isp.isp_org_id,
                IspSubscriber.customer_organization_id.in_(children),
                IspSubscriber.is_deleted.is_(False),
            )
        )
        if f.package_id is not None:
            q = q.where(IspSubscriber.package_id == f.package_id)
        if f.connection_type:
            q = q.where(IspSubscriberProfile.connection_type == f.connection_type)
        found = (await self.session.execute(q)).all()

        # router filter: any hotspot or PPPoE session on it, ever
        if router is not None:
            guests = set(
                (
                    await self.session.execute(
                        select(GuestSession.guest_id)
                        .where(GuestSession.router_id == router.id)
                        .distinct()
                    )
                ).scalars()
            )
            on_router = {s.id for s, _p, _t in found if s.guest_id in guests}
            if pppoe_on:
                from .pppoe_models import IspPppoeSession

                on_router |= set(
                    (
                        await self.session.execute(
                            select(IspPppoeSession.subscriber_id)
                            .where(
                                IspPppoeSession.router_id == router.id,
                                IspPppoeSession.subscriber_id.is_not(None),
                            )
                            .distinct()
                        )
                    ).scalars()
                )
            found = [r for r in found if r[0].id in on_router]

        ids = [s.id for s, _p, _t in found]
        customers = sorted({s.customer_organization_id for s, _p, _t in found})
        suspended = await IspSubscriber360Service._suspended_customers(
            SimpleNamespace(session=self.session), customers
        )
        kyc_pending: set[uuid.UUID] = set()
        if ids:
            kyc_pending = set(
                (
                    await self.session.execute(
                        select(IspSubscriberKyc.subscriber_id).where(
                            IspSubscriberKyc.subscriber_id.in_(ids),
                            IspSubscriberKyc.is_deleted.is_(False),
                            or_(
                                IspSubscriberKyc.verified_at.is_(None),
                                IspSubscriberKyc.installed_at.is_(None),
                            ),
                        )
                    )
                ).scalars()
            )

        # online: live hotspot sessions (and PPPoE when its flag is on)
        hs = select(GuestSession.guest_id).where(
            GuestSession.organization_id.in_(children),
            GuestSession.status == GuestSessionStatus.ACTIVE.value,
        )
        if router is not None:
            hs = hs.where(GuestSession.router_id == router.id)
        live_guests = list((await self.session.execute(hs)).scalars())
        sub_by_guest = {s.guest_id: s.id for s, _p, _t in found if s.guest_id}
        filtered = f.package_id is not None or bool(f.connection_type)
        hotspot_sessions = (
            sum(1 for g in live_guests if g in sub_by_guest)
            if filtered
            else len(live_guests)
        )
        online = {sub_by_guest[g] for g in live_guests if g in sub_by_guest}
        pppoe_sessions = 0
        if pppoe_on:
            from .pppoe_models import IspPppoeSession

            pq = select(IspPppoeSession.subscriber_id).where(
                IspPppoeSession.customer_organization_id.in_(children),
                IspPppoeSession.status == "active",
            )
            if router is not None:
                pq = pq.where(IspPppoeSession.router_id == router.id)
            live = list((await self.session.execute(pq)).scalars())
            in_view = set(ids)
            pppoe_sessions = (
                sum(1 for sid in live if sid in in_view) if filtered else len(live)
            )
            online |= {sid for sid in live if sid in in_view}

        churn_after = timedelta(
            days=(
                await compliance_settings(self.session, isp.isp_org_id)
            ).churn_after_days
        )
        clock = SimpleNamespace(now=lambda: now)
        rows = []
        for s, p, ptype in found:
            state = IspSubscriber360Service.display_state(
                clock, s, p, customer_suspended=s.customer_organization_id in suspended
            )
            bucket = logic.bucket_of(
                state,
                valid_until=s.valid_until,
                now=now,
                churn_after=churn_after,
                kyc_pending=s.id in kyc_pending,
            )
            rows.append(
                {
                    "sub": s,
                    "display_state": state,
                    "bucket": bucket,
                    "overlays": logic.overlays_of(
                        bucket,
                        valid_until=s.valid_until,
                        created_at=s.created_at,
                        package_type=ptype,
                        online=s.id in online,
                        now=now,
                        period_start=start,
                        period_end=end,
                    ),
                }
            )
        base["rows"] = rows
        base["sessions"] = {"hotspot": hotspot_sessions, "pppoe": pppoe_sessions}
        return base

    async def _pending_leads(
        self, isp: IspContext, children: list[uuid.UUID]
    ) -> int | None:
        """Open JAZE-5 leads, or None while ``ISP_APPS_ENABLED`` is off. A lead
        with no customer yet is counted only for an unconfined caller."""
        from sqlalchemy import func

        from .apps_common import get_isp_apps_settings
        from .apps_models import IspLead

        if not get_isp_apps_settings().enabled:
            return None
        cond = IspLead.customer_organization_id.in_(children or [uuid.UUID(int=0)])
        if isp.confined_customer_ids is None:
            cond = or_(cond, IspLead.customer_organization_id.is_(None))
        return int(
            (
                await self.session.execute(
                    select(func.count()).where(
                        IspLead.isp_organization_id == isp.isp_org_id,
                        IspLead.is_deleted.is_(False),
                        IspLead.status.in_(logic.OPEN_LEAD_STATUSES),
                        cond,
                    )
                )
            ).scalar_one()
        )

    async def summary(self, isp: IspContext, f: Filters) -> dict[str, Any]:
        data = await self._rows(isp, f)
        counts = logic.tally(data["rows"])
        sessions = data["sessions"]
        return {
            "tiles": counts,
            "buckets": list(logic.BUCKETS),
            "overlays": list(logic.OVERLAYS),
            "pending_leads": await self._pending_leads(isp, data["children"]),
            "online": {
                "hotspot_sessions": sessions["hotspot"],
                "pppoe_sessions": sessions["pppoe"],
                "total_sessions": sessions["hotspot"] + sessions["pppoe"],
                "subscribers": counts["online"],
                "pppoe_enabled": data["pppoe_enabled"],
            },
            "period": data["period"],
            "definitions": logic.DEFINITIONS,
            "as_of": data["now"].isoformat(),
        }

    async def drill(
        self, isp: IspContext, f: Filters, *, tile: str, page: int, page_size: int
    ) -> dict[str, Any]:
        from app.domains.organization.models import Organization

        from .plans_models import IspPackage
        from .subscriber_identity import subscriber_identifier

        if tile not in logic.TILE_KEYS:
            raise IspBadRequestError("Unknown tile")
        data = await self._rows(isp, f)
        rows = [r for r in data["rows"] if logic.in_tile(tile, r)]
        rows.sort(key=lambda r: (r["sub"].circuit_id or 0, str(r["sub"].id)))
        total = len(rows)
        pages = max(1, -(-total // page_size))
        chunk = rows[(page - 1) * page_size : page * page_size]
        cust_ids = {r["sub"].customer_organization_id for r in chunk}
        pkg_ids = {r["sub"].package_id for r in chunk if r["sub"].package_id}
        names = {}
        if cust_ids:
            names = dict(
                (
                    await self.session.execute(
                        select(Organization.id, Organization.name).where(
                            Organization.id.in_(cust_ids)
                        )
                    )
                ).all()
            )
        pkgs = {}
        if pkg_ids:
            pkgs = dict(
                (
                    await self.session.execute(
                        select(IspPackage.id, IspPackage.name).where(
                            IspPackage.id.in_(pkg_ids)
                        )
                    )
                ).all()
            )
        items = []
        for r in chunk:
            s = r["sub"]
            items.append(
                {
                    "id": str(s.id),
                    "identifier": subscriber_identifier(s.identifier, s.source),
                    "display_name": s.display_name,
                    "circuit_id": s.circuit_id,
                    "customer_id": str(s.customer_organization_id),
                    "customer_name": names.get(s.customer_organization_id),
                    "package_name": pkgs.get(s.package_id) if s.package_id else None,
                    "display_state": r["display_state"],
                    "bucket": r["bucket"],
                    "overlays": sorted(r["overlays"]),
                    "valid_until": s.valid_until.isoformat() if s.valid_until else None,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
            )
        return {
            "tile": tile,
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "period": data["period"],
        }


__all__ = ["PERIODS", "Filters", "IspDashboardService", "period_bounds"]

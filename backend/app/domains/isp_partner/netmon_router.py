"""NETMON-2 routes (ADDENDUM_06). ``ISP_NETMON_ENABLED`` (default OFF): every
route answers 404 ``ISP_NETMON_DISABLED`` while off.

* ``GET /isp/netmon/traffic?range=day|week|month`` -- one card per router in
  the caller's scope: the WAN series (JAZE-2 ``throughput_series`` over the
  existing SNMP snapshots, unchanged) or a "can't read this router" state
  with a fix hint that never names the tunnel.
* ``GET /isp/netmon/sessions/active`` -- live hotspot + PPPoE sessions across
  every router in scope.
* ``GET /isp/netmon/sessions/completed`` (+ ``/export.csv``, audited) --
  ended hotspot sessions and closed PPPoE sessions by subscriber / MAC / IP /
  plain-date range.

Scope: ``isp.child_ids()`` (customer confinement, narrowed by ZONE-1's
``scope_zone_id``). Guest identifiers are masked as on the per-router list
(F2); an ISP-entered subscriber identifier is shown as entered.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, date, datetime, time, timedelta
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.masking import mask_identifier
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from . import netmon as logic
from .constants import ISP_PARTNER_EXPORT, ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError, _err
from .http import ok
from .network_router import throughput_series
from .scoping import IspScope

IST = ZoneInfo("Asia/Kolkata")


class IspNetmonSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    netmon_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_netmon_settings() -> IspNetmonSettings:
    return IspNetmonSettings()


IspNetmonDisabledError = _err(
    "IspNetmonDisabledError", "ISP_NETMON_DISABLED", 404, "Not Found"
)


async def RequireNetmonEnabled() -> None:
    if not get_netmon_settings().netmon_enabled:
        raise IspNetmonDisabledError()


netmon_router = APIRouter(prefix="/netmon", tags=["ISP Partner: network monitoring"])
_ON = [Depends(RequireNetmonEnabled)]
AUDIT_SESSIONS_EXPORT = "isp_completed_sessions_exported"


def _iso(v: datetime | None) -> str | None:
    return v.isoformat() if v else None


def _ist(v: datetime | None) -> str | None:
    if v is None:
        return None
    a = v if v.tzinfo else v.replace(tzinfo=UTC)
    return a.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")


async def _scope(isp: IspContext, isp_customer_id: uuid.UUID | None) -> list[uuid.UUID]:
    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
        return [isp_customer_id]
    return await isp.child_ids()


async def _routers(db: AsyncSession, customers: list[uuid.UUID]) -> list[Any]:
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization
    from app.domains.router.models import Router

    if not customers:
        return []
    return list(
        (
            await db.execute(
                select(Router, Organization.name, Location.name)
                .join(Organization, Organization.id == Router.organization_id)
                .outerjoin(Location, Location.id == Router.location_id)
                .where(
                    Router.organization_id.in_(customers),
                    Router.is_deleted.is_(False),
                )
                .order_by(Organization.name, Router.name)
            )
        ).all()
    )


# --------------------------------------------------------------------------
# traffic
# --------------------------------------------------------------------------


@netmon_router.get("/traffic", dependencies=_ON + isp_guards(ISP_PARTNER_READ))
async def traffic(
    request: Request,
    range_: str = Query(default="day", alias="range", pattern="^(day|week|month)$"),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.router.vendor_capabilities import is_controller_managed_row
    from app.domains.router_provisioning.models import RouterHealthSnapshot as H

    now = datetime.now(UTC)
    since = now - logic.RANGES[range_]
    rows = await _routers(db, await _scope(isp, isp_customer_id))
    ids = [r.id for r, _c, _l in rows]
    snaps: dict[uuid.UUID, list[Any]] = {}
    if ids:
        for s in (
            await db.execute(
                select(H)
                .where(
                    H.router_id.in_(ids),
                    H.recorded_at >= since,
                    H.interface_traffic_counters.is_not(None),
                )
                .order_by(H.router_id, H.recorded_at)
            )
        ).scalars():
            snaps.setdefault(s.router_id, []).append(s)
    cards = []
    for r, cust, loc in rows:
        series = throughput_series(snaps.get(r.id, []))
        wan, basis = logic.pick_wan(series)
        points = logic.downsample(
            series.get(wan, []) if wan else [], since=since, until=now
        )
        readable, reason, hint = logic.readability(
            status=r.status,
            last_seen_at=r.last_seen_at,
            snmp_enabled=bool(getattr(r, "snmp_enabled", False)),
            snmp_last_poll_status=getattr(r, "snmp_last_poll_status", None),
            has_series=bool(points),
            now=now,
            controller_managed=is_controller_managed_row(r),
        )
        cards.append(
            {
                "isp_router_id": str(r.id),
                "name": r.name,
                "customer_name": cust,
                "location_name": loc,
                "status": r.status,
                "last_seen_ist": _ist(r.last_seen_at),
                "readable": readable,
                "reason": reason,
                "hint": hint,
                "wan_interface": wan,
                "wan_basis": basis,
                "points": points,
                "peak_in_mbps": max((p["in_mbps"] for p in points), default=None),
                "peak_out_mbps": max((p["out_mbps"] for p in points), default=None),
            }
        )
    return ok(
        request,
        {
            "range": range_,
            "since": since.isoformat(),
            "until": now.isoformat(),
            "routers": cards,
            "basis": (
                "WAN is the interface whose name usually carries the uplink "
                "(wan, pppoe-out, lte, ether1, sfp1), else the busiest interface."
            ),
        },
        "Router traffic",
    )


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------


async def _subscribers_by_guest(
    db: AsyncSession, guest_ids: set[uuid.UUID], customers: list[uuid.UUID]
) -> dict[uuid.UUID, Any]:
    from .plans_models import IspSubscriber

    if not guest_ids:
        return {}
    return {
        s.guest_id: s
        for s in (
            await db.execute(
                select(IspSubscriber).where(
                    IspSubscriber.guest_id.in_(guest_ids),
                    IspSubscriber.customer_organization_id.in_(customers),
                    IspSubscriber.is_deleted.is_(False),
                )
            )
        ).scalars()
    }


def _who(ident: str | None, sub: Any) -> str | None:
    from .subscriber_identity import subscriber_identifier

    if sub is not None:
        return subscriber_identifier(sub.identifier, sub.source)
    return mask_identifier(ident)


async def _hotspot(
    db: AsyncSession,
    customers: list[uuid.UUID],
    *,
    active: bool,
    router_id: uuid.UUID | None = None,
    mac: str | None = None,
    ip: str | None = None,
    guest_ids: set[uuid.UUID] | None = None,
    search: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int,
) -> list[dict[str, Any]]:
    from app.domains.guest.constants import GuestSessionStatus
    from app.domains.guest.models import Guest, GuestDevice, GuestSession
    from app.domains.router.models import Router

    if not customers:
        return []
    q = (
        select(GuestSession, GuestDevice.mac_address, Guest.identifier, Router.name)
        .outerjoin(GuestDevice, GuestDevice.id == GuestSession.device_id)
        .outerjoin(Guest, Guest.id == GuestSession.guest_id)
        .outerjoin(Router, Router.id == GuestSession.router_id)
        .where(GuestSession.organization_id.in_(customers))
    )
    active_v = GuestSessionStatus.ACTIVE.value
    if active:
        q = q.where(GuestSession.status == active_v).order_by(
            GuestSession.started_at.desc()
        )
    else:
        q = q.where(
            GuestSession.status != active_v, GuestSession.ended_at.is_not(None)
        ).order_by(GuestSession.ended_at.desc())
        if since is not None:
            q = q.where(GuestSession.ended_at >= since)
        if until is not None:
            q = q.where(GuestSession.started_at < until)
    if router_id is not None:
        q = q.where(GuestSession.router_id == router_id)
    if mac:
        q = q.where(GuestDevice.mac_address == mac)
    if ip:
        q = q.where(GuestSession.ip_address == ip)
    if guest_ids is not None:
        if not guest_ids:
            return []
        q = q.where(GuestSession.guest_id.in_(guest_ids))
    if search:
        q = q.where(Guest.identifier.ilike(f"%{search}%"))
    rows = (await db.execute(q.limit(limit))).all()
    subs = await _subscribers_by_guest(
        db, {gs.guest_id for gs, *_ in rows if gs.guest_id}, customers
    )
    now = datetime.now(UTC)
    out = []
    for gs, mac_, ident, rname in rows:
        sub = subs.get(gs.guest_id)
        end = gs.ended_at if not active else None
        out.append(
            {
                "kind": "hotspot",
                "session_id": str(gs.id),
                "isp_router_id": str(gs.router_id) if gs.router_id else None,
                "router_name": rname,
                "who": _who(ident, sub),
                "subscriber_id": str(sub.id) if sub else None,
                "circuit_id": sub.circuit_id if sub else None,
                "mac": mac_,
                "ip": gs.ip_address,
                "started_at": _iso(gs.started_at),
                "ended_at": _iso(end),
                "uptime_seconds": int(((end or now) - gs.started_at).total_seconds())
                if gs.started_at
                else None,
                "bytes_down": int(gs.bytes_downloaded or 0),
                "bytes_up": int(gs.bytes_uploaded or 0),
                # LEFTOVERS: the guest domain's own recorded reason (RADIUS
                # Acct-Stop / timeout / block sweeps), None while live.
                "end_reason": gs.disconnect_reason if end else None,
                "_sort": end or gs.started_at,
            }
        )
    return out


async def _pppoe(
    db: AsyncSession,
    customers: list[uuid.UUID],
    *,
    active: bool,
    router_id: uuid.UUID | None = None,
    mac: str | None = None,
    ip: str | None = None,
    subscriber_ids: set[uuid.UUID] | None = None,
    search: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int,
) -> list[dict[str, Any]]:
    from app.domains.router.models import Router

    from .plans_models import IspSubscriber
    from .pppoe_config import get_isp_pppoe_settings
    from .pppoe_models import IspPppoeSession as P

    if not customers or not get_isp_pppoe_settings().enabled:
        return []
    q = (
        select(P, Router.name, IspSubscriber)
        .outerjoin(Router, Router.id == P.router_id)
        .outerjoin(IspSubscriber, IspSubscriber.id == P.subscriber_id)
        .where(P.customer_organization_id.in_(customers), P.is_deleted.is_(False))
    )
    if active:
        q = q.where(P.status == "active").order_by(P.started_at.desc())
    else:
        q = q.where(P.status == "closed").order_by(P.stopped_at.desc().nulls_last())
        if since is not None:
            q = q.where(or_(P.stopped_at >= since, P.stopped_at.is_(None)))
        if until is not None:
            q = q.where(P.started_at < until)
    if router_id is not None:
        q = q.where(P.router_id == router_id)
    if mac:
        q = q.where(P.calling_station_id.ilike(mac))
    if ip:
        q = q.where(P.framed_ip_address == ip)
    if subscriber_ids is not None:
        if not subscriber_ids:
            return []
        q = q.where(P.subscriber_id.in_(subscriber_ids))
    if search:
        q = q.where(P.username.ilike(f"%{search}%"))
    now = datetime.now(UTC)
    out = []
    for p, rname, sub in (await db.execute(q.limit(limit))).all():
        end = p.stopped_at if not active else None
        out.append(
            {
                "kind": "pppoe",
                "session_id": str(p.id),
                "isp_router_id": str(p.router_id) if p.router_id else None,
                "router_name": rname,
                "who": p.username,
                "subscriber_id": str(p.subscriber_id) if p.subscriber_id else None,
                "circuit_id": sub.circuit_id if sub else None,
                "mac": p.calling_station_id,
                "ip": p.framed_ip_address,
                "started_at": _iso(p.started_at),
                "ended_at": _iso(end),
                "uptime_seconds": int(((end or now) - p.started_at).total_seconds())
                if p.started_at
                else None,
                "bytes_down": int(p.bytes_downloaded or 0),
                "bytes_up": int(p.bytes_uploaded or 0),
                "end_reason": p.terminate_cause if not active else None,
                "_sort": end or p.started_at,
            }
        )
    return out


def _page(items: list[dict], page: int, page_size: int) -> dict:
    items.sort(
        key=lambda x: x["_sort"] or datetime.min.replace(tzinfo=UTC), reverse=True
    )
    total = len(items)
    chunk = items[(page - 1) * page_size : page * page_size]
    for i in chunk:
        i.pop("_sort", None)
    return {
        "items": chunk,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
    }


@netmon_router.get("/sessions/active", dependencies=_ON + isp_guards(ISP_PARTNER_READ))
async def active_sessions(
    request: Request,
    isp_router_id: uuid.UUID | None = Query(default=None),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    kind: str | None = Query(default=None, pattern="^(hotspot|pppoe)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    customers = await _scope(isp, isp_customer_id)
    if isp_router_id is not None:
        r = await IspScope.assert_router(isp, isp_router_id)
        customers = [c for c in customers if c == r.organization_id]
    cap = 2000
    items: list[dict] = []
    if kind in (None, "hotspot"):
        items += await _hotspot(
            db, customers, active=True, router_id=isp_router_id, limit=cap
        )
    if kind in (None, "pppoe"):
        items += await _pppoe(
            db, customers, active=True, router_id=isp_router_id, limit=cap
        )
    data = _page(items, page, page_size)
    data["capped"] = len(items) >= cap
    return ok(request, data, "Active sessions")


def _norm_mac(v: str | None) -> str | None:
    from app.domains.ipdr.formatting import normalize_mac

    return normalize_mac(v) if v else None


async def _completed(
    db: AsyncSession,
    isp: IspContext,
    *,
    isp_customer_id: uuid.UUID | None,
    subscriber_id: uuid.UUID | None,
    mac: str | None,
    ip: str | None,
    search: str | None,
    date_from: date | None,
    date_to: date | None,
    kind: str | None,
    limit: int,
) -> list[dict]:
    from .plans_models import IspSubscriber

    today = datetime.now(IST).date()
    d1 = date_to or today
    d0 = date_from or (d1 - timedelta(days=6))
    if d1 < d0 or (d1 - d0).days > 92:
        raise IspBadRequestError("The range is 1 to 93 days, start before end")
    since = datetime.combine(d0, time.min, tzinfo=IST).astimezone(UTC)
    until = datetime.combine(d1 + timedelta(days=1), time.min, tzinfo=IST).astimezone(
        UTC
    )
    customers = await _scope(isp, isp_customer_id)
    guest_ids: set[uuid.UUID] | None = None
    sub_ids: set[uuid.UUID] | None = None
    if subscriber_id is not None:
        sub = await db.get(IspSubscriber, subscriber_id)
        if (
            sub is None
            or sub.is_deleted
            or sub.isp_organization_id != isp.isp_org_id
            or sub.customer_organization_id not in customers
        ):
            raise IspBadRequestError("Unknown subscriber", field="subscriber_id")
        guest_ids = {sub.guest_id} if sub.guest_id else set()
        sub_ids = {sub.id}
    m = _norm_mac(mac)
    if mac and m is None:
        raise IspBadRequestError("Not a MAC address", field="mac")
    term = (search or "").strip() or None
    items: list[dict] = []
    if kind in (None, "hotspot"):
        items += await _hotspot(
            db,
            customers,
            active=False,
            mac=m,
            ip=ip,
            guest_ids=guest_ids,
            search=term,
            since=since,
            until=until,
            limit=limit,
        )
    if kind in (None, "pppoe"):
        items += await _pppoe(
            db,
            customers,
            active=False,
            mac=m,
            ip=ip,
            subscriber_ids=sub_ids,
            search=term,
            since=since,
            until=until,
            limit=limit,
        )
    return items


def _completed_params(
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    mac: str | None = Query(default=None, max_length=17),
    ip: str | None = Query(default=None, max_length=45),
    search: str | None = Query(default=None, max_length=100),
    date_from: date | None = Query(default=None),
    date_to: date | None = Query(default=None),
    kind: str | None = Query(default=None, pattern="^(hotspot|pppoe)$"),
) -> dict[str, Any]:
    return {
        "isp_customer_id": isp_customer_id,
        "subscriber_id": subscriber_id,
        "mac": mac,
        "ip": ip,
        "search": search,
        "date_from": date_from,
        "date_to": date_to,
        "kind": kind,
    }


@netmon_router.get(
    "/sessions/completed", dependencies=_ON + isp_guards(ISP_PARTNER_READ)
)
async def completed_sessions(
    request: Request,
    f: dict = Depends(_completed_params),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    items = await _completed(db, isp, **f, limit=5000)
    return ok(request, _page(items, page, page_size), "Completed sessions")


_CSV = (
    "Type",
    "Router",
    "Who",
    "Circuit ID",
    "MAC",
    "IP",
    "Start (IST)",
    "End (IST)",
    "Duration (s)",
    "Download (bytes)",
    "Upload (bytes)",
    "End reason",
)


@netmon_router.get(
    "/sessions/completed/export.csv", dependencies=_ON + isp_guards(ISP_PARTNER_EXPORT)
)
async def completed_sessions_csv(
    f: dict = Depends(_completed_params),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    from app.domains.ipdr.formatting import csv_safe

    items = await _completed(db, isp, **f, limit=50000)
    items.sort(
        key=lambda x: x["_sort"] or datetime.min.replace(tzinfo=UTC), reverse=True
    )
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action=AUDIT_SESSIONS_EXPORT,
        entity_type="organization",
        entity_id=isp.isp_org_id,
        description="Completed sessions exported",
        event_metadata={
            "console": "isp",
            "rows": len(items),
            **{k: (str(v) if v is not None else None) for k, v in f.items()},
        },
        organization_id=isp.isp_org_id,
    )
    await db.commit()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV)
    for i in items:
        w.writerow(
            [
                csv_safe("" if v is None else v)
                for v in (
                    i["kind"],
                    i["router_name"],
                    i["who"],
                    i["circuit_id"],
                    i["mac"],
                    i["ip"],
                    _ist(datetime.fromisoformat(i["started_at"]))
                    if i["started_at"]
                    else None,
                    _ist(datetime.fromisoformat(i["ended_at"]))
                    if i["ended_at"]
                    else None,
                    i["uptime_seconds"],
                    i["bytes_down"],
                    i["bytes_up"],
                    i["end_reason"],
                )
            ]
        )
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return Response(
        content=buf.getvalue().encode(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="sessions-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


__all__ = ["get_netmon_settings", "netmon_router"]

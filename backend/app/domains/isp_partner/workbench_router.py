"""SUB360-2: the Subscriber 360 support workbench (read model + precise
disconnect). Contract: LANE_NOTES [SUB360-2].

Everything is assembled from the lanes' own code, called unchanged:
JAZE-1 (subscriber lookup, live sessions, timeline event), JAZE-2
(``auth_slots``), JAZE-5 (``HelpdeskService.list_tickets``), JAZE-6
(``IspPppoeService``), ZONE-1 (zone path), TR-069 devices. No new table.

``ISP_SUB360_WORKBENCH_ENABLED`` (default OFF): both routes 404
``ISP_SUB360_WORKBENCH_DISABLED`` and the 360 page renders as before.

Scope: the subscriber is resolved through ``IspPlansService.subscriber``
(ISP + customer confinement -> 404), so another ISP, or a technician confined
to other customers, gets 404 on both routes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import func, select

from app.domains.guest.dependencies import get_guest_service
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator, get_rbac_repository

from .constants import ISP_SUBSCRIBERS_DISCONNECT  # RBAC-FIX
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import _err
from .http import ok
from .plans_router import SUBS_READ, get_plans_service
from .plans_service import IspPlansService


class IspWorkbenchSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    sub360_workbench_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_workbench_settings() -> IspWorkbenchSettings:
    return IspWorkbenchSettings()


IspWorkbenchDisabledError = _err(
    "IspWorkbenchDisabledError", "ISP_SUB360_WORKBENCH_DISABLED", 404, "Not Found"
)


async def RequireWorkbenchEnabled() -> None:
    if not get_workbench_settings().sub360_workbench_enabled:
        raise IspWorkbenchDisabledError()


workbench_router = APIRouter(tags=["ISP Partner: subscriber 360 workbench"])
_ON = [Depends(RequireWorkbenchEnabled)]
OPEN_TICKET_STATUSES = ("open", "in_progress", "on_hold")


class DisconnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session_id: uuid.UUID | None = None
    mac: str | None = Field(default=None, max_length=17)


def _iso(v: datetime | None) -> str | None:
    return v.isoformat() if v else None


def _norm_mac(v: str | None) -> str | None:
    from .enforcement import norm_mac

    return norm_mac(v)


# --------------------------------------------------------------------------
# pieces
# --------------------------------------------------------------------------


async def _hotspot_live(db: Any, s: Any) -> list[tuple[Any, dict]]:
    """(GuestSession, view) for the subscriber's live hotspot sessions."""
    from app.domains.guest.constants import GuestSessionStatus
    from app.domains.guest.models import GuestDevice, GuestSession
    from app.domains.router.models import Router

    if not s.guest_id:
        return []
    rows = (
        await db.execute(
            select(GuestSession, GuestDevice.mac_address, Router.name)
            .outerjoin(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .outerjoin(Router, Router.id == GuestSession.router_id)
            .where(
                GuestSession.guest_id == s.guest_id,
                GuestSession.organization_id == s.customer_organization_id,
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
            )
            .order_by(GuestSession.started_at.desc())
        )
    ).all()
    now = datetime.now(UTC)
    out = []
    for g, mac, rname in rows:
        out.append(
            (
                g,
                {
                    "kind": "hotspot",
                    "session_id": str(g.id),
                    "router_id": str(g.router_id) if g.router_id else None,
                    "router_name": rname,
                    "nas": rname,
                    # Hotspot sessions do not record an interface.
                    "interface": None,
                    "ip": g.ip_address,
                    "mac": mac,
                    "started_at": _iso(g.started_at),
                    "uptime_seconds": int((now - g.started_at).total_seconds())
                    if g.started_at
                    else 0,
                    "bytes_down": int(g.bytes_downloaded or 0),
                    "bytes_up": int(g.bytes_uploaded or 0),
                },
            )
        )
    return out


async def _pppoe_live(db: Any, s: Any) -> list[tuple[Any, dict]]:
    from app.domains.router.models import Router

    from .pppoe_config import get_isp_pppoe_settings
    from .pppoe_models import IspPppoeSession

    if not get_isp_pppoe_settings().enabled:
        return []
    rows = (
        await db.execute(
            select(IspPppoeSession, Router.name)
            .outerjoin(Router, Router.id == IspPppoeSession.router_id)
            .where(
                IspPppoeSession.subscriber_id == s.id,
                IspPppoeSession.customer_organization_id == s.customer_organization_id,
                IspPppoeSession.status == "active",
                IspPppoeSession.is_deleted.is_(False),
            )
            .order_by(IspPppoeSession.started_at.desc())
        )
    ).all()
    nas_names: dict[uuid.UUID, str | None] = {}
    nas_ids = {p.nas_client_id for p, _ in rows if p.nas_client_id}
    if nas_ids:
        from app.domains.guest.models import RadiusNasClient

        for nid, name, ident in (
            await db.execute(
                select(
                    RadiusNasClient.id,
                    RadiusNasClient.name,
                    RadiusNasClient.nas_identifier,
                ).where(RadiusNasClient.id.in_(nas_ids))
            )
        ).all():
            nas_names[nid] = name or ident
    now = datetime.now(UTC)
    out = []
    for p, rname in rows:
        out.append(
            (
                p,
                {
                    "kind": "pppoe",
                    "session_id": str(p.id),
                    "router_id": str(p.router_id) if p.router_id else None,
                    "router_name": rname,
                    "nas": nas_names.get(p.nas_client_id) or rname,
                    "interface": p.nas_port_id,
                    "ip": p.framed_ip_address,
                    "mac": _norm_mac(p.calling_station_id),
                    "started_at": _iso(p.started_at),
                    "uptime_seconds": int((now - p.started_at).total_seconds())
                    if p.started_at
                    else 0,
                    "bytes_down": int(p.bytes_downloaded or 0),
                    "bytes_up": int(p.bytes_uploaded or 0),
                },
            )
        )
    return out


async def _zone_path(db: Any, isp: IspContext, zone_id: uuid.UUID | None) -> list[dict]:
    if zone_id is None:
        return []
    from .zones_scope import ancestry, parent_map, zone_rows

    rows = await zone_rows(db, isp.isp_org_id)
    names = {z.id: z.name for z, _ in rows}
    if zone_id not in names:
        return []
    return [
        {"id": str(z), "name": names[z]} for z in ancestry(parent_map(rows), zone_id)
    ]


async def _tickets(
    db: Any, isp: IspContext, s: Any, permissions: set[str]
) -> tuple[int | None, list[dict] | None]:
    from .apps_common import get_isp_apps_settings
    from .apps_helpdesk import HelpdeskService

    if not get_isp_apps_settings().enabled or "isp_apps.read" not in permissions:
        return None, None
    svc = HelpdeskService(db)
    open_count = 0
    for status in OPEN_TICKET_STATUSES:
        _items, total = await svc.list_tickets(
            isp, subscriber_id=s.id, status=status, page=1, page_size=1
        )
        open_count += int(total)
    items, _total = await svc.list_tickets(
        isp, subscriber_id=s.id, page=1, page_size=20
    )
    return open_count, items


async def _services(db: Any, s: Any, profile: Any) -> list[dict]:
    from .plans_models import IspPackage, IspSpeedGroup

    pkg_name, speed = None, None
    if s.package_id:
        row = (
            await db.execute(
                select(
                    IspPackage.name,
                    IspSpeedGroup.download_kbps,
                    IspSpeedGroup.upload_kbps,
                )
                .outerjoin(IspSpeedGroup, IspSpeedGroup.id == IspPackage.speed_group_id)
                .where(IspPackage.id == s.package_id)
            )
        ).first()
        if row is not None:
            pkg_name = row[0]
            if row[1] is not None:
                speed = f"{_kbps(row[1])}/{_kbps(row[2])}"
    out: list[dict] = [{"kind": "isp", "package_name": pkg_name, "speed": speed}]
    serial = (getattr(profile, "ont_serial", None) or "").strip()
    if serial:
        from app.domains.tr069.models import Tr069Device

        d = (
            await db.execute(
                select(Tr069Device)
                .where(
                    Tr069Device.isp_organization_id == s.isp_organization_id,
                    Tr069Device.customer_organization_id == s.customer_organization_id,
                    func.lower(Tr069Device.serial_number) == serial.lower(),
                    Tr069Device.is_deleted.is_(False),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if d is not None:
            window = timedelta(
                seconds=max(2 * (d.periodic_inform_interval_s or 300), 900)
            )
            out.append(
                {
                    "kind": "tr069",
                    "cpe_id": str(d.id),
                    "serial": d.serial_number,
                    "model": d.model,
                    "online": bool(
                        d.last_inform_at
                        and datetime.now(UTC) - d.last_inform_at <= window
                    ),
                    "last_inform_at": _iso(d.last_inform_at),
                }
            )
    return out


def _kbps(v: int | None) -> str:
    if not v:
        return "unlimited"
    return f"{v // 1024} Mbps" if v >= 1024 and v % 1024 == 0 else f"{v} Kbps"


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------


@workbench_router.get(
    "/subscribers/{subscriber_id}/workbench", dependencies=_ON + isp_guards(SUBS_READ)
)
async def get_workbench(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    plans: IspPlansService = Depends(get_plans_service),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> dict:
    from .enforcement import auth_slots
    from .plans_models import IspPackage
    from .pppoe_config import get_isp_pppoe_settings
    from .pppoe_models import IspPppoeCredential
    from .router import effective_isp_permissions
    from .subscriber360_models import IspSubscriberProfile

    s = await plans.subscriber(isp, subscriber_id)  # ISP + confinement -> 404
    db = plans.session
    profile = (
        await db.execute(
            select(IspSubscriberProfile).where(
                IspSubscriberProfile.subscriber_id == s.id,
                IspSubscriberProfile.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    permissions = set(await effective_isp_permissions(isp, access_validator))
    open_tickets, tickets = await _tickets(db, isp, s, permissions)
    live = [v for _r, v in await _hotspot_live(db, s)] + [
        v for _r, v in await _pppoe_live(db, s)
    ]
    slots = await auth_slots(db, s.id)
    cred = (
        await db.execute(
            select(IspPppoeCredential.status).where(
                IspPppoeCredential.subscriber_id == s.id,
                IspPppoeCredential.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    package = None
    if s.package_id:
        name = (
            await db.execute(
                select(IspPackage.name).where(IspPackage.id == s.package_id)
            )
        ).scalar_one_or_none()
        package = {"id": str(s.package_id), "name": name}
    now = datetime.now(UTC)
    return ok(
        request,
        {
            "subscriber_id": str(s.id),
            "breadcrumb": {
                "zone_path": await _zone_path(db, isp, s.zone_id),
                "package": package,
            },
            "validity": {
                "valid_until": _iso(s.valid_until),
                "seconds_left": int((s.valid_until - now).total_seconds())
                if s.valid_until
                else None,
            },
            "open_tickets": open_tickets,
            "tickets": tickets,
            "live": live,
            "auth": {
                "hotspot": True,
                "pppoe": cred == "active",
                "mac_bound": slots["mac_bound"],
                "static_ip": slots["static_ip"],
            },
            "services": await _services(db, s, profile),
            "pppoe_enabled": get_isp_pppoe_settings().enabled,
        },
        "Subscriber workbench",
    )


@workbench_router.post(
    "/subscribers/{subscriber_id}/workbench/disconnect",
    dependencies=_ON + isp_guards(ISP_SUBSCRIBERS_DISCONNECT),
)
async def workbench_disconnect(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: DisconnectRequest | None = Body(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    plans: IspPlansService = Depends(get_plans_service),
    guest_service=Depends(get_guest_service),  # noqa: B008
    audit=Depends(get_rbac_repository),  # noqa: B008
) -> dict:
    """End the subscriber's live sessions: one (``session_id``), those of one
    device (``mac``), or all. Hotspot via ``GuestService.disconnect_session``
    (the JAZE-1 path); PPPoE via ``IspPppoeService.disconnect`` (JAZE-6, only
    while ISP_PPPOE_ENABLED is on)."""
    from .pppoe_service import IspPppoeService
    from .subscriber360_service import IspSubscriber360Service

    s = await plans.subscriber(isp, subscriber_id)  # ISP + confinement -> 404
    db = plans.session
    want_id = str(payload.session_id) if payload and payload.session_id else None
    want_mac = _norm_mac(payload.mac) if payload and payload.mac else None

    def wanted(view: dict) -> bool:
        if want_id and view["session_id"] != want_id:
            return False
        return not (want_mac and (view["mac"] or "").upper() != want_mac)

    ended: list[str] = []
    unconfirmed: list[str] = []
    for g, view in await _hotspot_live(db, s):
        if not wanted(view):
            continue
        try:
            updated = await guest_service.disconnect_session(
                session_id=g.id,
                requesting_organization_id=s.customer_organization_id,
                actor_user_id=isp.user_id,
                reason="isp_subscriber_disconnect",
            )
            ended.append(view["session_id"])
            if getattr(updated, "disconnect_enforced", None) is False:
                unconfirmed.append(view["session_id"])
        except Exception:  # noqa: BLE001 -- a router failure is reported, not a 5xx
            unconfirmed.append(view["session_id"])
    pppoe = IspPppoeService(session=db, audit=audit)
    for p, view in await _pppoe_live(db, s):
        if not wanted(view):
            continue
        try:
            r = await pppoe.disconnect(isp, p.id)
            if r.get("ended"):
                ended.append(view["session_id"])
            else:
                unconfirmed.append(view["session_id"])
        except Exception:  # noqa: BLE001 -- unreachable NAS is reported per session
            unconfirmed.append(view["session_id"])
    if ended or unconfirmed:
        svc360 = IspSubscriber360Service(plans=plans, guest_service=guest_service)
        await svc360.event(
            isp,
            s,
            "disconnected",
            f"{len(ended)} session(s) ended from the workbench",
            reason="isp_subscriber_disconnect",
            ended=len(ended),
            unconfirmed=len(unconfirmed),
            mac=want_mac,
            session_id=want_id,
        )
    await db.commit()
    return ok(request, {"ended": ended, "unconfirmed": unconfirmed}, "Disconnect sent")


__all__ = ["get_workbench_settings", "workbench_router"]

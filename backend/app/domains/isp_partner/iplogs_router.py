"""IPLOGS-SELFSERVE routes: an ISP turns on IP logs for its own router.

``ISP_IPLOGS_SELFSERVE_ENABLED`` (default OFF): every route answers 404
``ISP_IPLOGS_DISABLED`` while off, so nothing changes for anyone until the
flag is set.

* ``GET  /isp/routers/{isp_router_id}/ip-logs`` -- what is arriving from this
  router (system logs, connection logs, NAT translations), the overall state,
  warnings (behind another NAT, clock off, RouterOS 6, ...).
* ``GET  /isp/routers/{isp_router_id}/ip-logs/script`` -- the one paste
  script (``iplogs_script``) and the one that undoes it.
* ``POST /isp/routers/{isp_router_id}/ip-logs/enable`` -- records that this
  router is meant to send, so its connection records are STORED: the flow
  writer stores a router's records only while its
  ``router_traffic_flow_export`` row is enabled, and keeps the source port
  (IPDR needs it) only with ``ipdr_ports``. Until now only the Master console
  wrote that row. Audited ``isp_ip_logs_enabled``.
* ``POST /isp/routers/{isp_router_id}/ip-logs/disable`` -- intent off (records
  stop being stored); audited ``isp_ip_logs_disabled``.
* ``GET  /isp/ip-logs/routers`` -- one status row per router in scope.

Scope: a single router goes through ``IspScope.assert_router`` (foreign or
out-of-confinement = 404); the list runs over ``isp.child_ids()``. Path ids
are ``isp_router_id`` (never a scope-alias name).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query, Request
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_db_session
from app.domains.device_logs.constants import Attribution, LogSource
from app.domains.device_logs.models import DeviceLogEvent, RouterRemoteLogging
from app.domains.device_logs.routeros import hub_tunnel_address, router_tag
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import is_controller_managed_row
from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord
from app.domains.traffic_flow.models import RouterTrafficFlowExport
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer
from app.domains.wireguard.validators import hub_reserved_ip

from . import iplogs_status as st
from .constants import ISP_PARTNER_EXECUTE, ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import _err
from .http import ok
from .iplogs_script import (
    IpLogsTargets,
    render_disable_script,
    render_enable_script,
    safe_identity,
)
from .scoping import IspScope

IST = ZoneInfo("Asia/Kolkata")
AUDIT_ENABLED = "isp_ip_logs_enabled"
AUDIT_DISABLED = "isp_ip_logs_disabled"
#: How far back "last line at" looks. Older than this reads as never.
SYSLOG_LOOKBACK = timedelta(days=30)
FLOW_LOOKBACK = timedelta(days=7)


class IspIpLogsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    iplogs_selfserve_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_iplogs_settings() -> IspIpLogsSettings:
    return IspIpLogsSettings()


IspIpLogsDisabledError = _err(
    "IspIpLogsDisabledError", "ISP_IPLOGS_DISABLED", 404, "Not Found"
)
IspIpLogsNeedsLinkError = _err(
    "IspIpLogsNeedsLinkError",
    "ISP_IPLOGS_NEEDS_LINK",
    409,
    "Finish the router's setup script first: IP logs travel over its "
    "management connection, which is not set up yet.",
)
IspIpLogsNotSupportedError = _err(
    "IspIpLogsNotSupportedError",
    "ISP_IPLOGS_NOT_SUPPORTED",
    409,
    "IP logs can be turned on for MikroTik routers only.",
)


async def RequireIpLogsEnabled() -> None:
    if not get_iplogs_settings().iplogs_selfserve_enabled:
        raise IspIpLogsDisabledError()


iplogs_router = APIRouter(tags=["ISP Partner: IP logs self-serve"])
_ON = [Depends(RequireIpLogsEnabled)]


def _aware(v: datetime | None) -> datetime | None:
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=UTC)


def _iso(v: datetime | None) -> str | None:
    a = _aware(v)
    return a.isoformat() if a else None


def _ist(v: datetime | None) -> str | None:
    a = _aware(v)
    return a.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S") if a else None


def _collectors() -> dict[str, bool]:
    s = get_settings()
    return {
        "syslog": bool(s.device_logs_enabled),
        "flows": bool(
            s.traffic_flow_enabled
            and s.traffic_flow_records_enabled
            and s.traffic_flow_agent_url
        ),
    }


# --------------------------------------------------------------------------
# reads
# --------------------------------------------------------------------------


async def _link(
    db: AsyncSession, router_id: uuid.UUID
) -> tuple[WireGuardPeer | None, WireGuardServer | None]:
    peer = (
        await db.execute(
            select(WireGuardPeer).where(
                WireGuardPeer.router_id == router_id,
                WireGuardPeer.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if peer is None:
        return None, None
    server = await db.get(WireGuardServer, peer.server_id)
    return peer, server


def _blocker(router: Any, peer: Any, server: Any) -> str | None:
    if (router.vendor or "mikrotik").lower() != "mikrotik" or (
        is_controller_managed_row(router)
    ):
        return "not_mikrotik"
    if peer is None or server is None:
        return "needs_link"
    return None


def _targets(router: Any, peer: Any, server: Any) -> IpLogsTargets:
    s = get_settings()
    return IpLogsTargets(
        router_id=router.id,
        router_name=router.name,
        source_address=peer.tunnel_ip_address,
        syslog_host=s.device_logs_remote_host
        or hub_tunnel_address(server.tunnel_network_cidr),
        syslog_port=int(s.device_logs_remote_port),
        flow_host=hub_reserved_ip(server.tunnel_network_cidr),
        flow_port=int(s.traffic_flow_collector_port),
    )


async def _intent(
    db: AsyncSession, router_ids: list[uuid.UUID]
) -> tuple[dict[uuid.UUID, Any], dict[uuid.UUID, Any]]:
    syslog = {
        r.router_id: r
        for r in (
            await db.execute(
                select(RouterRemoteLogging).where(
                    RouterRemoteLogging.router_id.in_(router_ids),
                    RouterRemoteLogging.is_deleted.is_(False),
                )
            )
        ).scalars()
    }
    flows = {
        r.router_id: r
        for r in (
            await db.execute(
                select(RouterTrafficFlowExport).where(
                    RouterTrafficFlowExport.router_id.in_(router_ids),
                    RouterTrafficFlowExport.is_deleted.is_(False),
                )
            )
        ).scalars()
    }
    return syslog, flows


async def _grouped(db: AsyncSession, stmt: Any) -> dict[uuid.UUID, Any]:
    return {rid: v for rid, v in (await db.execute(stmt)).all()}


async def _arrivals(
    db: AsyncSession, router_ids: list[uuid.UUID], now: datetime
) -> dict[str, dict[uuid.UUID, Any]]:
    """Last-at and last-hour counts per router for the three pipes. Every
    query is keyed on the routers already resolved in scope."""
    if not router_ids:
        return {k: {} for k in ("syslog", "syslog_n", "flows", "flows_n", "nat")}
    e, f = DeviceLogEvent, TrafficFlowRecord
    hour = now - timedelta(hours=1)
    syslog_base = (e.router_id.in_(router_ids), e.source == LogSource.SYSLOG.value)
    flow_base = (f.router_id.in_(router_ids),)
    nat_row = or_(f.nat_src_address.is_not(None), f.nat_event.is_not(None))
    return {
        "syslog": await _grouped(
            db,
            select(e.router_id, func.max(e.received_at))
            .where(*syslog_base, e.received_at >= now - SYSLOG_LOOKBACK)
            .group_by(e.router_id),
        ),
        "syslog_n": await _grouped(
            db,
            select(e.router_id, func.count())
            .where(*syslog_base, e.received_at >= hour)
            .group_by(e.router_id),
        ),
        "flows": await _grouped(
            db,
            select(f.router_id, func.max(f.window_start))
            .where(*flow_base, f.window_start >= now - FLOW_LOOKBACK)
            .group_by(f.router_id),
        ),
        "flows_n": await _grouped(
            db,
            select(f.router_id, func.count())
            .where(*flow_base, f.window_start >= hour)
            .group_by(f.router_id),
        ),
        "nat": await _grouped(
            db,
            select(f.router_id, func.max(f.window_start))
            .where(*flow_base, nat_row, f.window_start >= now - FLOW_LOOKBACK)
            .group_by(f.router_id),
        ),
    }


def _pipe(state: str, last: datetime | None, count: int | None) -> dict[str, Any]:
    return {
        "state": state,
        "last_at": _iso(last),
        "last_at_ist": _ist(last),
        "count_last_hour": int(count or 0),
    }


def _status_row(
    router: Any,
    *,
    peer: Any,
    server: Any,
    intent_syslog: Any,
    intent_flows: Any,
    arrivals: dict[str, dict[uuid.UUID, Any]],
    now: datetime,
    names: dict[str, str | None],
) -> dict[str, Any]:
    collectors = _collectors()
    blocker = _blocker(router, peer, server)
    syslog_on = bool(intent_syslog and intent_syslog.enabled)
    flows_on = bool(intent_flows and intent_flows.enabled)
    rid = router.id
    last_syslog = _aware(arrivals["syslog"].get(rid))
    last_flow = _aware(arrivals["flows"].get(rid))
    last_nat = _aware(arrivals["nat"].get(rid))
    pipes = {
        "syslog": st.pipe_state(
            collector_on=collectors["syslog"],
            set_up=syslog_on,
            last_at=last_syslog,
            now=now,
            stale_after=st.SYSLOG_STALE,
        ),
        "flows": st.pipe_state(
            collector_on=collectors["flows"],
            set_up=flows_on,
            last_at=last_flow,
            now=now,
            stale_after=st.FLOW_STALE,
        ),
        "nat": st.pipe_state(
            collector_on=collectors["flows"],
            set_up=flows_on,
            last_at=last_nat,
            now=now,
            stale_after=st.FLOW_STALE,
        ),
    }
    overall = st.overall_state(
        blocker=blocker,
        router_online=router.status == RouterStatus.ONLINE.value,
        pipes=pipes,
    )
    return {
        "isp_router_id": str(rid),
        "router_name": router.name,
        "isp_customer_id": str(router.organization_id),
        "customer_name": names.get("customer"),
        "isp_location_id": str(router.location_id) if router.location_id else None,
        "location_name": names.get("location"),
        "router_status": router.status,
        "routeros_version": router.routeros_version,
        "state": overall,
        "state_label": st.state_label(overall, pipes),
        "lagging_pipes": st.lagging_pipes(pipes) if overall == st.PARTIAL else [],
        "blocker": blocker,
        "set_up": syslog_on and flows_on,
        "set_up_at": _iso(
            (intent_flows.updated_at if intent_flows else None)
            or (intent_syslog.updated_at if intent_syslog else None)
        ),
        "collectors": collectors,
        "pipes": {
            "syslog": _pipe(
                pipes["syslog"], last_syslog, arrivals["syslog_n"].get(rid)
            ),
            "flows": _pipe(pipes["flows"], last_flow, arrivals["flows_n"].get(rid)),
            "nat": _pipe(pipes["nat"], last_nat, None),
        },
    }


async def _detail_extras(
    db: AsyncSession, router: Any, peer: Any, now: datetime
) -> dict[str, Any]:
    """The per-router reads behind the warnings (single router only)."""
    e, f = DeviceLogEvent, TrafficFlowRecord
    hour, day = now - timedelta(hours=1), now - timedelta(hours=24)
    latest = (
        await db.execute(
            select(e.received_at, e.device_time)
            .where(
                e.router_id == router.id,
                e.source == LogSource.SYSLOG.value,
                e.device_time.is_not(None),
                e.received_at >= hour,
            )
            .order_by(e.received_at.desc())
            .limit(1)
        )
    ).first()
    offset = None
    if latest is not None:
        offset = (_aware(latest[0]) - _aware(latest[1])).total_seconds()
    untagged = (
        await db.execute(
            select(func.count()).where(
                e.router_id == router.id,
                e.source == LogSource.SYSLOG.value,
                e.claimed_tag.is_(None),
                e.received_at >= hour,
            )
        )
    ).scalar_one()
    mismatch = 0
    if peer is not None:
        # Rows refused on tag are stored with no router; they are found by
        # this router's own source address and named as a count only.
        mismatch = (
            await db.execute(
                select(func.count()).where(
                    e.source_ip == peer.tunnel_ip_address,
                    e.attribution == Attribution.TAG_MISMATCH.value,
                    e.received_at >= day,
                )
            )
        ).scalar_one()
    translated = [
        str(v)
        for (v,) in (
            await db.execute(
                select(f.nat_src_address)
                .where(
                    f.router_id == router.id,
                    f.nat_src_address.is_not(None),
                    f.window_start >= day,
                )
                .distinct()
                .limit(5)
            )
        ).all()
    ]
    nat_events = (
        await db.execute(
            select(func.count()).where(
                f.router_id == router.id,
                f.nat_event.is_not(None),
                f.window_start >= hour,
            )
        )
    ).scalar_one()
    return {
        "clock_offset_seconds": offset,
        "untagged_lines": int(untagged or 0),
        "tag_mismatch_lines": int(mismatch or 0),
        "translated_ips": translated,
        "nat_events_seen": bool(nat_events),
    }


async def _names(isp: IspContext, router: Any) -> dict[str, str | None]:
    orgs = await isp.repository.names(Organization, [router.organization_id])
    locs = (
        await isp.repository.names(Location, [router.location_id])
        if router.location_id
        else {}
    )
    return {
        "customer": orgs.get(router.organization_id),
        "location": locs.get(router.location_id),
    }


async def _detail(
    db: AsyncSession, isp: IspContext, router: Any, now: datetime
) -> dict[str, Any]:
    peer, server = await _link(db, router.id)
    syslog, flows = await _intent(db, [router.id])
    arrivals = await _arrivals(db, [router.id], now)
    row = _status_row(
        router,
        peer=peer,
        server=server,
        intent_syslog=syslog.get(router.id),
        intent_flows=flows.get(router.id),
        arrivals=arrivals,
        now=now,
        names=await _names(isp, router),
    )
    extras = await _detail_extras(db, router, peer, now)
    row["warnings"] = st.warnings_for(
        routeros_version=router.routeros_version,
        public_ip=router.public_ip_address,
        translated_ips=extras["translated_ips"],
        clock_offset_seconds=extras["clock_offset_seconds"],
        tag_mismatch_lines=extras["tag_mismatch_lines"],
        untagged_lines=extras["untagged_lines"],
        flows_receiving=row["pipes"]["flows"]["state"] == st.RECEIVING,
        nat_events_seen=extras["nat_events_seen"],
        collector_flows_on=row["collectors"]["flows"],
    )
    row["clock_offset_seconds"] = extras["clock_offset_seconds"]
    row["blocker_hint"] = {
        "needs_link": "Paste the router's setup script first. IP logs travel over "
        "its management connection, and this router does not have one yet.",
        "not_mikrotik": "IP logs can be turned on for MikroTik routers only.",
    }.get(row["blocker"] or "")
    return row


def _now() -> datetime:
    return datetime.now(UTC)


@iplogs_router.get(
    "/routers/{isp_router_id}/ip-logs", dependencies=_ON + isp_guards(ISP_PARTNER_READ)
)
async def router_ip_logs(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    router = await IspScope.assert_router(isp, isp_router_id)
    return ok(request, await _detail(db, isp, router, _now()), "IP logs status")


@iplogs_router.get(
    "/routers/{isp_router_id}/ip-logs/script",
    dependencies=_ON + isp_guards(ISP_PARTNER_EXECUTE),
)
async def router_ip_logs_script(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    router = await IspScope.assert_router(isp, isp_router_id)
    peer, server = await _link(db, router.id)
    blocker = _blocker(router, peer, server)
    data: dict[str, Any] = {
        "isp_router_id": str(router.id),
        "available": blocker is None,
        "blocker": blocker,
        "enable_script": None,
        "disable_script": None,
        "filename": None,
        "router_name_on_device": safe_identity(router.name, router.id),
        "tag": router_tag(router.id),
    }
    if blocker is None:
        t = _targets(router, peer, server)
        data.update(
            enable_script=render_enable_script(t),
            disable_script=render_disable_script(t),
            filename=f"wyfy-ip-logs-{safe_identity(router.name, router.id)}.rsc",
        )
    return ok(request, data, "IP logs script")


async def _any_row(db: AsyncSession, model: Any, router_id: uuid.UUID) -> Any:
    # router_id is UNIQUE across soft-deleted rows too, so a deleted row is
    # restored rather than a second one inserted.
    return (
        await db.execute(select(model).where(model.router_id == router_id))
    ).scalar_one_or_none()


async def _set_intent(
    db: AsyncSession, router: Any, t: IpLogsTargets | None, *, on: bool, actor: Any
) -> dict[str, bool]:
    before: dict[str, bool] = {}
    syslog = await _any_row(db, RouterRemoteLogging, router.id)
    flows = await _any_row(db, RouterTrafficFlowExport, router.id)
    before["syslog"] = bool(syslog and not syslog.is_deleted and syslog.enabled)
    before["flows"] = bool(flows and not flows.is_deleted and flows.enabled)
    note = "Set up by the ISP with the IP logs paste script (not read back)"
    if on:
        assert t is not None
        cfg = t.syslog()
        if syslog is None:
            syslog = RouterRemoteLogging(router_id=router.id, created_by=actor)
            db.add(syslog)
        syslog.is_deleted, syslog.deleted_at = False, None
        syslog.enabled = True
        syslog.remote_host, syslog.remote_port = cfg.remote_host, cfg.remote_port
        syslog.src_address, syslog.tag = cfg.src_address, cfg.tag
        syslog.verify_detail = note
        syslog.updated_by = actor
        if flows is None:
            flows = RouterTrafficFlowExport(router_id=router.id, created_by=actor)
            db.add(flows)
        flows.is_deleted, flows.deleted_at = False, None
        flows.enabled = True
        flows.target_host, flows.target_port = t.flow_host, t.flow_port
        flows.src_address, flows.export_version = t.source_address, "ipfix"
        # IPDR needs the subscriber's own source port (see module docstring).
        flows.ipdr_ports = True
        flows.last_verdict_detail = note
        flows.updated_by = actor
    else:
        for row in (syslog, flows):
            if row is not None and not row.is_deleted:
                row.enabled = False
                row.updated_by = actor
    return before


async def _toggle(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext,
    db: AsyncSession,
    audit: RBACRepositoryProtocol,
    *,
    on: bool,
) -> dict:
    router = await IspScope.assert_router(isp, isp_router_id)
    peer, server = await _link(db, router.id)
    blocker = _blocker(router, peer, server)
    if on and blocker == "not_mikrotik":
        raise IspIpLogsNotSupportedError()
    if on and blocker == "needs_link":
        raise IspIpLogsNeedsLinkError()
    targets = _targets(router, peer, server) if on else None
    actor = isp.user_id
    before = await _set_intent(db, router, targets, on=on, actor=actor)
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action=AUDIT_ENABLED if on else AUDIT_DISABLED,
        entity_type="router",
        entity_id=router.id,
        description="IP logs turned on" if on else "IP logs turned off",
        event_metadata={
            "console": "isp",
            "isp_organization_id": str(isp.isp_org_id),
            "customer_organization_id": str(router.organization_id),
            "was": before,
        },
        organization_id=isp.isp_org_id,
    )
    await db.commit()
    return ok(request, await _detail(db, isp, router, _now()), "IP logs updated")


@iplogs_router.post(
    "/routers/{isp_router_id}/ip-logs/enable",
    dependencies=_ON + isp_guards(ISP_PARTNER_EXECUTE),
)
async def enable_router_ip_logs(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    return await _toggle(request, isp_router_id, isp, db, audit, on=True)


@iplogs_router.post(
    "/routers/{isp_router_id}/ip-logs/disable",
    dependencies=_ON + isp_guards(ISP_PARTNER_EXECUTE),
)
async def disable_router_ip_logs(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    return await _toggle(request, isp_router_id, isp, db, audit, on=False)


@iplogs_router.get("/ip-logs/routers", dependencies=_ON + isp_guards(ISP_PARTNER_READ))
async def ip_logs_routers(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
        customers = [isp_customer_id]
    else:
        customers = await isp.child_ids()
    now = _now()
    routers = (
        list(
            (
                await db.execute(
                    select(Router)
                    .where(
                        Router.organization_id.in_(customers),
                        Router.is_deleted.is_(False),
                    )
                    .order_by(Router.name)
                )
            )
            .scalars()
            .all()
        )
        if customers
        else []
    )
    ids = [r.id for r in routers]
    syslog, flows = await _intent(db, ids) if ids else ({}, {})
    arrivals = await _arrivals(db, ids, now)
    peers = (
        {
            p.router_id: p
            for p in (
                await db.execute(
                    select(WireGuardPeer).where(
                        WireGuardPeer.router_id.in_(ids),
                        WireGuardPeer.is_deleted.is_(False),
                    )
                )
            ).scalars()
        }
        if ids
        else {}
    )
    servers = (
        {
            s.id: s
            for s in (
                await db.execute(
                    select(WireGuardServer).where(
                        WireGuardServer.id.in_({p.server_id for p in peers.values()})
                    )
                )
            ).scalars()
        }
        if peers
        else {}
    )
    org_names = (
        await isp.repository.names(
            Organization, list({r.organization_id for r in routers})
        )
        if routers
        else {}
    )
    loc_ids = list({r.location_id for r in routers if r.location_id})
    loc_names = await isp.repository.names(Location, loc_ids) if loc_ids else {}
    items = []
    for r in routers:
        peer = peers.get(r.id)
        items.append(
            _status_row(
                r,
                peer=peer,
                server=servers.get(peer.server_id) if peer else None,
                intent_syslog=syslog.get(r.id),
                intent_flows=flows.get(r.id),
                arrivals=arrivals,
                now=now,
                names={
                    "customer": org_names.get(r.organization_id),
                    "location": loc_names.get(r.location_id),
                },
            )
        )
    summary: dict[str, int] = {}
    for i in items:
        summary[i["state"]] = summary.get(i["state"], 0) + 1
    return ok(
        request,
        {"items": items, "summary": summary, "collectors": _collectors()},
        "IP logs routers",
    )

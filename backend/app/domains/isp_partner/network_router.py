"""JAZE-2 network views (ADDENDUM_05 J13/J20/J21). Read-only.

* ``GET /isp/routers/{isp_router_id}/health/live`` -- one live RouterOS API
  read: CPU (total + per core), memory, uptime, version, board, and every
  interface's rx/tx bit rate and packet rate (two counter reads one second
  apart; ``/interface monitor-traffic`` is a streaming command and is not
  used). Unreachable router -> ``reachable: false`` with the reason.
* ``GET /isp/routers/{isp_router_id}/health/history?hours=`` -- the existing
  ``router_health_snapshots`` series (CPU, memory, clients) and per-interface
  throughput derived from successive SNMP counter snapshots (only when SNMP
  polling is on for that router; said so in ``interfaces_source``).
* ``GET /isp/routers/{isp_router_id}/sessions/active`` -- live guest sessions
  on the router (hotspot today; PPPoE when Phase 2b lands). Guest
  identifiers are masked (F2).
* ``GET /isp/tr069/summary`` -- CPE tiles: total / active / new today /
  configured today / offline.
* ``GET /isp/tr069/devices/{cpe_id}/optical`` -- optical RX power from the
  CPE's cached parameters, with a colour band.

The router's own connection credentials never leave the backend.
"""

from __future__ import annotations

import asyncio
import re
import time as _time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.masking import mask_identifier
from app.database.session import get_db_session

from .constants import ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .scoping import IspScope

network_router = APIRouter(tags=["ISP Partner: network health"])

_LIVE_TIMEOUT_S = 8


# --------------------------------------------------------------------------
# Live router read (J20 + J13 "now")
# --------------------------------------------------------------------------


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _uptime_seconds(v: str | None) -> int | None:
    """RouterOS uptime like ``3w2d04:05:06`` or ``1d2h3m4s``."""
    if not v:
        return None
    s = str(v).strip()
    total = 0
    clock = re.search(r"(\d+):(\d{2}):(\d{2})$", s)
    if clock:
        h, m, sec = (int(x) for x in clock.groups())
        total += h * 3600 + m * 60 + sec
        s = s[: clock.start()]
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    matched = False
    for num, unit in re.findall(r"(\d+)([wdhms])", s):
        total += int(num) * units[unit]
        matched = True
    if not clock and not matched:
        return None
    return total


def interface_rates(
    first: list[dict[str, Any]], second: list[dict[str, Any]], seconds: float
) -> list[dict[str, Any]]:
    """Two ``/interface`` reads -> per-interface bps/pps. Counter wraps and
    resets (negative deltas) yield ``None`` rather than a fake spike."""
    before = {r.get("name"): r for r in first if r.get("name")}
    out = []
    for r in second:
        name = r.get("name")
        if not name or name == "lo":
            continue
        a = before.get(name, {})

        def rate(field: str, mult: int = 1, _a=a, _r=r) -> float | None:
            x, y = _int(_a.get(field)), _int(_r.get(field))
            if x is None or y is None or y < x or seconds <= 0:
                return None
            return round((y - x) * mult / seconds, 1)

        out.append(
            {
                "name": name,
                "type": r.get("type"),
                "running": str(r.get("running", "")).lower() == "true",
                "disabled": str(r.get("disabled", "")).lower() == "true",
                "rx_bps": rate("rx-byte", 8),
                "tx_bps": rate("tx-byte", 8),
                "rx_pps": rate("rx-packet"),
                "tx_pps": rate("tx-packet"),
                "rx_bytes": _int(r.get("rx-byte")),
                "tx_bytes": _int(r.get("tx-byte")),
                "rx_errors": _int(r.get("rx-error")),
                "tx_errors": _int(r.get("tx-error")),
                "rx_drops": _int(r.get("rx-drop")),
                "tx_drops": _int(r.get("tx-drop")),
            }
        )
    return out


def _read_live_sync(host: str, username: str, secret: str, port: int | None) -> dict:
    from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
    from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter

    adapter = MikroTikAdapter()
    creds = DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host=host,
        username=username,
        secret=secret,
        port=port,
        timeout_seconds=_LIVE_TIMEOUT_S,
    )
    api = adapter._connect_api(creds)  # noqa: SLF001 -- read-only reuse of the gateway's own connector
    try:
        res = next(iter(api.path("system", "resource")), {})
        try:
            cores = list(api.path("system", "resource", "cpu"))
        except Exception:  # noqa: BLE001 -- older RouterOS: no per-core menu
            cores = []
        try:
            board = next(iter(api.path("system", "routerboard")), {})
        except Exception:  # noqa: BLE001 -- CHR/x86 have no routerboard menu
            board = {}
        t0 = _time.monotonic()
        first = [dict(r) for r in api.path("interface")]
        _time.sleep(1.0)
        second = [dict(r) for r in api.path("interface")]
        elapsed = _time.monotonic() - t0
    finally:
        adapter._safe_close(api)  # noqa: SLF001
    total_mem, free_mem = _int(res.get("total-memory")), _int(res.get("free-memory"))
    return {
        "reachable": True,
        "cpu_load_percent": _int(res.get("cpu-load")),
        "cpu_count": _int(res.get("cpu-count")),
        "cpu_cores": [
            {"cpu": c.get("cpu"), "load_percent": _int(c.get("load"))} for c in cores
        ],
        "cpu_model": res.get("cpu"),
        "memory_total_bytes": total_mem,
        "memory_free_bytes": free_mem,
        "memory_used_percent": (
            round(100 * (total_mem - free_mem) / total_mem, 1)
            if total_mem and free_mem is not None
            else None
        ),
        "uptime": res.get("uptime"),
        "uptime_seconds": _uptime_seconds(res.get("uptime")),
        "version": res.get("version"),
        "board_name": res.get("board-name"),
        "architecture": res.get("architecture-name"),
        "model": board.get("model"),
        "serial_number": board.get("serial-number"),
        "interfaces": interface_rates(first, second, elapsed or 1.0),
    }


@network_router.get(
    "/routers/{isp_router_id}/health/live", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def router_health_live(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    from app.domains.router.crypto import decrypt_secret

    router = await IspScope.assert_router(isp, isp_router_id)
    base = {"router_id": str(router.id), "read_at": datetime.now(UTC).isoformat()}
    host = router.management_ip_address or router.public_ip_address
    secret = (
        decrypt_secret(router.api_credentials_encrypted)
        if router.api_credentials_encrypted
        else None
    )
    if (router.vendor or "mikrotik").lower() != "mikrotik":
        return ok(request, {**base, "reachable": False, "reason": "not_mikrotik"})
    if not host or not router.api_username or not secret:
        return ok(request, {**base, "reachable": False, "reason": "not_set_up"})
    try:
        data = await asyncio.wait_for(
            asyncio.to_thread(
                _read_live_sync,
                host,
                router.api_username,
                secret,
                getattr(router, "api_port", None),
            ),
            timeout=_LIVE_TIMEOUT_S * 3,
        )
    except Exception as exc:  # noqa: BLE001 -- the page says "unreachable"
        return ok(
            request,
            {
                **base,
                "reachable": False,
                "reason": "unreachable",
                "detail": type(exc).__name__,
            },
            "Router not reachable",
        )
    return ok(request, {**base, **data}, "Router health")


# --------------------------------------------------------------------------
# History (J13)
# --------------------------------------------------------------------------


def throughput_series(snapshots: list[Any]) -> dict[str, list[dict[str, Any]]]:
    """Per-interface Mbps between successive SNMP counter snapshots."""
    series: dict[str, list[dict[str, Any]]] = {}
    prev: dict[str, tuple[datetime, int, int]] = {}
    for snap in snapshots:
        for c in snap.interface_traffic_counters or []:
            name = c.get("if_name") or str(c.get("if_index"))
            inn, out = _int(c.get("in_octets")), _int(c.get("out_octets"))
            if inn is None or out is None:
                continue
            p = prev.get(name)
            prev[name] = (snap.recorded_at, inn, out)
            if p is None:
                continue
            dt = (snap.recorded_at - p[0]).total_seconds()
            if dt <= 0 or inn < p[1] or out < p[2]:
                continue
            series.setdefault(name, []).append(
                {
                    "at": snap.recorded_at.isoformat(),
                    "in_mbps": round((inn - p[1]) * 8 / dt / 1e6, 3),
                    "out_mbps": round((out - p[2]) * 8 / dt / 1e6, 3),
                }
            )
    return series


@network_router.get(
    "/routers/{isp_router_id}/health/history",
    dependencies=isp_guards(ISP_PARTNER_READ),
)
async def router_health_history(
    request: Request,
    isp_router_id: uuid.UUID,
    hours: int = Query(default=24, ge=1, le=24 * 31),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.router_provisioning.models import RouterHealthSnapshot

    router = await IspScope.assert_router(isp, isp_router_id)
    since = datetime.now(UTC) - timedelta(hours=hours)
    snaps = list(
        (
            await db.execute(
                select(RouterHealthSnapshot)
                .where(
                    RouterHealthSnapshot.router_id == router.id,
                    RouterHealthSnapshot.recorded_at >= since,
                )
                .order_by(RouterHealthSnapshot.recorded_at)
                .limit(5000)
            )
        ).scalars()
    )
    interfaces = throughput_series(snaps)
    return ok(
        request,
        {
            "router_id": str(router.id),
            "hours": hours,
            "points": [
                {
                    "at": s.recorded_at.isoformat(),
                    "cpu_percent": s.cpu_usage_percent,
                    "memory_percent": s.memory_usage_percent,
                    "uptime_seconds": s.uptime_seconds,
                    "clients": s.connected_clients_count,
                    "status": s.health_status,
                }
                for s in snaps
            ],
            "interfaces": interfaces,
            "interfaces_source": "snmp" if interfaces else "none",
        },
        "Router history",
    )


# --------------------------------------------------------------------------
# Active sessions (J20)
# --------------------------------------------------------------------------


@network_router.get(
    "/routers/{isp_router_id}/sessions/active",
    dependencies=isp_guards(ISP_PARTNER_READ),
)
async def router_active_sessions(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.guest.constants import GuestSessionStatus
    from app.domains.guest.models import Guest, GuestDevice, GuestSession

    from .plans_models import IspSubscriber
    from .subscriber_identity import subscriber_identifier

    router = await IspScope.assert_router(isp, isp_router_id)
    rows = (
        await db.execute(
            select(GuestSession, GuestDevice.mac_address, Guest.identifier)
            .outerjoin(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .outerjoin(Guest, Guest.id == GuestSession.guest_id)
            .where(
                GuestSession.router_id == router.id,
                GuestSession.organization_id == router.organization_id,
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
            )
            .order_by(GuestSession.started_at.desc())
            .limit(500)
        )
    ).all()
    guest_ids = [gs.guest_id for gs, _m, _i in rows if gs.guest_id]
    subs = {}
    if guest_ids:
        for s in (
            await db.execute(
                select(IspSubscriber).where(
                    IspSubscriber.guest_id.in_(guest_ids),
                    IspSubscriber.customer_organization_id == router.organization_id,
                    IspSubscriber.is_deleted.is_(False),
                )
            )
        ).scalars():
            subs[s.guest_id] = s
    now = datetime.now(UTC)
    out = []
    for gs, mac, ident in rows:
        sub = subs.get(gs.guest_id)
        out.append(
            {
                "session_id": str(gs.id),
                "kind": "pppoe" if (gs.auth_method or "") == "pppoe" else "hotspot",
                "started_at": gs.started_at.isoformat(),
                "uptime_seconds": int((now - gs.started_at).total_seconds()),
                "ip": gs.ip_address,
                "mac": mac,
                "guest": subscriber_identifier(ident, sub.source if sub else None)
                if sub
                else mask_identifier(ident),
                "subscriber_id": str(sub.id) if sub else None,
                "circuit_id": sub.circuit_id if sub else None,
                "bytes_down": gs.bytes_downloaded,
                "bytes_up": gs.bytes_uploaded,
                "last_activity_at": gs.last_activity_at.isoformat()
                if gs.last_activity_at
                else None,
            }
        )
    return ok(
        request, {"router_id": str(router.id), "sessions": out}, "Active sessions"
    )


# --------------------------------------------------------------------------
# TR-069 tiles + optical power (J21)
# --------------------------------------------------------------------------

#: Known RX power parameters, most specific first.
OPTICAL_RX_PATHS = (
    "Device.Optical.Interface.1.Stats.OpticalSignalLevel",
    "Device.Optical.Interface.1.OpticalSignalLevel",
    "InternetGatewayDevice.WANDevice.1.X_GponInterafceConfig.RXPower",
    "InternetGatewayDevice.WANDevice.1.X_GponInterfaceConfig.RXPower",
    "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.RXPower",
    "InternetGatewayDevice.WANDevice.1.X_ZTE-COM_WANPONInterfaceConfig.RXPower",
    "InternetGatewayDevice.WANDevice.1.X_HW_OpticInfo.RxPower",
)


def _cached_value(cache: dict[str, Any], path: str) -> Any:
    v = cache.get(path)
    if isinstance(v, dict):
        v = v.get("value", v.get("_value"))
        if isinstance(v, list) and v:
            v = v[0]
    return v


def optical_reading(cache: dict[str, Any] | None) -> dict[str, Any]:
    """dBm + band. Vendors report dBm, 0.1 dBm, 0.01 dBm or 0.001 dBm; the
    value is scaled down by 10 until it is in a plausible -60..+10 range.
    ``raw`` is always returned so a wrong guess is visible."""
    cache = cache or {}
    for path in OPTICAL_RX_PATHS:
        raw = _cached_value(cache, path)
        if raw in (None, ""):
            continue
        try:
            v = float(str(raw).strip())
        except ValueError:
            continue
        dbm = v
        while abs(dbm) > 60:
            dbm /= 10
        band = (
            "good"
            if -25 <= dbm <= -8
            else "warn"
            if -27 <= dbm < -25 or -8 < dbm <= -3
            else "bad"
        )
        return {
            "available": True,
            "dbm": round(dbm, 2),
            "raw": raw,
            "path": path,
            "band": band,
        }
    return {"available": False, "dbm": None, "raw": None, "path": None, "band": None}


@network_router.get("/tr069/summary", dependencies=isp_guards(ISP_PARTNER_READ))
async def tr069_summary(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.tr069.models import Tr069Device, Tr069Task

    q = select(Tr069Device).where(
        Tr069Device.isp_organization_id == isp.isp_org_id,
        Tr069Device.is_deleted.is_(False),
    )
    if isp.confined_customer_ids is not None:
        q = q.where(Tr069Device.customer_organization_id.in_(await isp.child_ids()))
    devices = list((await db.execute(q)).scalars())
    now = datetime.now(UTC)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    active = offline = new_today = unassigned = 0
    for d in devices:
        window = timedelta(seconds=max(2 * (d.periodic_inform_interval_s or 300), 900))
        if d.last_inform_at and now - d.last_inform_at <= window:
            active += 1
        else:
            offline += 1
        if d.first_seen_at and d.first_seen_at >= day_start:
            new_today += 1
        if d.customer_organization_id is None:
            unassigned += 1
    ids = [d.id for d in devices]
    configured = 0
    if ids:
        configured = (
            await db.execute(
                select(func.count(func.distinct(Tr069Task.device_id))).where(
                    Tr069Task.device_id.in_(ids),
                    Tr069Task.completed_at >= day_start,
                    Tr069Task.status.in_(("done", "completed", "succeeded")),
                )
            )
        ).scalar_one()
    return ok(
        request,
        {
            "total": len(devices),
            "active": active,
            "offline": offline,
            "new_today": new_today,
            "configured_today": int(configured or 0),
            "unassigned": unassigned,
            "day_start_utc": day_start.isoformat(),
        },
        "TR-069 summary",
    )


@network_router.get(
    "/tr069/devices/{cpe_id}/optical", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def tr069_optical(
    request: Request,
    cpe_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    device = await IspScope.assert_cpe(isp, cpe_id)
    data = optical_reading(device.params_cache)
    data["cpe_id"] = str(device.id)
    data["params_refreshed_at"] = (
        device.params_refreshed_at.isoformat() if device.params_refreshed_at else None
    )
    return ok(request, data, "Optical power")


__all__ = ["interface_rates", "network_router", "optical_reading", "throughput_series"]

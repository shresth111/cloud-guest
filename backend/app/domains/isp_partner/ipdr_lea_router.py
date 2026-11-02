"""IPDR-2 routes (ADDENDUM_06). ``ISP_IPDR_LEA_ENABLED`` (default OFF): every
route answers 404 ``ISP_IPDR_LEA_DISABLED`` while off.

* ``POST /isp/compliance/lea-trace`` -- reverse-IP trace report (JSON, PDF or
  XLSX). ``isp_ipdr.export`` (seeded for owner/admin only) AND an owner/admin
  role check; a mandatory LEA reference; every run is audit-logged (also the
  on-screen JSON run). Builds on JAZE-3's CGNAT lookup unchanged, plus the
  raw NAT rows with event vs receipt time.
* ``GET /isp/compliance/retention`` -- oldest NAT / session row per router vs
  the 2-year target, and the days with zero rows while the router was up.
  Read only: nothing here (or anywhere in this lane) prunes data.
* ``GET /isp/compliance/ipdr-field-coverage`` -- the DoT field statement.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import and_, cast, func, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.ipdr.dependencies import get_ipdr_service
from app.domains.ipdr.service import IpdrService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from . import compliance_logic as logic
from . import ipdr_lea as lea
from .compliance_router import _audit, _lookup, get_compliance_service
from .compliance_service import IspComplianceService
from .constants import ISP_IPDR_EXPORT, ISP_IPDR_READ, UNCONFINABLE_ROLES
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError, _err
from .http import ok
from .scoping import IspScope


class IspIpdrLeaSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    ipdr_lea_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_ipdr_lea_settings() -> IspIpdrLeaSettings:
    return IspIpdrLeaSettings()


IspIpdrLeaDisabledError = _err(
    "IspIpdrLeaDisabledError", "ISP_IPDR_LEA_DISABLED", 404, "Not Found"
)
IspLeaOwnerAdminOnlyError = _err(
    "IspLeaOwnerAdminOnlyError",
    "ISP_LEA_OWNER_ADMIN_ONLY",
    403,
    "Only an ISP Owner or Admin can run a reverse-IP trace report",
)


async def RequireIpdrLeaEnabled() -> None:
    if not get_ipdr_lea_settings().ipdr_lea_enabled:
        raise IspIpdrLeaDisabledError()


ipdr_lea_router = APIRouter(prefix="/compliance", tags=["ISP Partner: IPDR / LEA"])
_ON = [Depends(RequireIpdrLeaEnabled)]
AUDIT_LEA_TRACE = "isp_lea_trace_report"


class LeaTraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    public_ip: str = Field(max_length=64)
    public_port: int | None = Field(default=None, ge=0, le=65535)
    at: datetime
    tz: str = Field(default="Asia/Kolkata", max_length=64)
    tolerance_seconds: int = Field(default=60, ge=0, le=900)
    protocol: str | None = Field(default=None, pattern="^(tcp|udp|icmp|any)?$")
    dst_ip: str | None = Field(default=None, max_length=64)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    isp_customer_id: uuid.UUID | None = None
    #: The LEA notice / requisition number. Mandatory.
    lea_reference: str = Field(min_length=3, max_length=100)
    reason: str = Field(min_length=3, max_length=500)
    #: Flag rows whose receipt lags the event by more than this.
    gap_minutes: int = Field(default=5, ge=1, le=1440)
    format: str = Field(default="json", pattern="^(json|pdf|xlsx)$")

    @field_validator("lea_reference", "reason")
    @classmethod
    def _printable(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("control characters are not allowed")
        return v


def _query(body: LeaTraceRequest) -> logic.LookupQuery:
    try:
        zone = ZoneInfo(body.tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise IspBadRequestError(
            "Unknown time zone", field="tz", reason="ISP_QUERY_INVALID"
        ) from exc
    try:
        ip = logic.normalize_ip(body.public_ip)
        dst = logic.normalize_ip(body.dst_ip) if body.dst_ip else None
    except ValueError as exc:
        raise IspBadRequestError("Not an IP address", field="public_ip") from exc
    moment = body.at if body.at.tzinfo else body.at.replace(tzinfo=zone)
    return logic.LookupQuery(
        public_ip=ip,
        public_port=body.public_port,
        at=moment.astimezone(UTC),
        tolerance=timedelta(seconds=body.tolerance_seconds),
        protocol={"tcp": 6, "udp": 17, "icmp": 1}.get(body.protocol or ""),
        dst_ip=dst,
        dst_port=body.dst_port,
    )


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None


async def _nat_rows(
    db: AsyncSession,
    q: logic.LookupQuery,
    routers: dict[uuid.UUID, str],
    *,
    gap_minutes: int,
) -> list[dict[str, Any]]:
    """Raw NAT rows for the public address in the window, with event and
    receipt time kept apart."""
    from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord as F

    if not routers:
        return []
    cond = [
        F.router_id.in_(list(routers)),
        F.nat_src_address == cast(q.public_ip, INET),
        F.window_start >= q.since - timedelta(minutes=10),
        F.window_start <= q.until + timedelta(minutes=10),
    ]
    if q.public_port is not None:
        cond.append(F.nat_src_port == q.public_port)
    if q.dst_ip is not None:
        cond.append(F.dst_address == cast(q.dst_ip, INET))
    if q.dst_port is not None:
        cond.append(F.dst_port == q.dst_port)
    rows = (
        await db.execute(
            select(F).where(and_(*cond)).order_by(F.window_start, F.id).limit(500)
        )
    ).scalars()
    out = []
    for r in rows:
        start, end = r.flow_start, r.flow_end or r.flow_start
        if start is not None and (start > q.until or (end or start) < q.since):
            continue  # the router's own time says it is outside the window
        out.append(
            {
                "router_id": str(r.router_id),
                "router_name": routers.get(r.router_id),
                "private_ip": str(r.src_address),
                "private_port": r.src_port,
                "public_ip": str(r.nat_src_address),
                "public_port": r.nat_src_port,
                "dst_ip": str(r.dst_address),
                "dst_port": r.dst_port,
                "protocol": r.protocol,
                "nat_event": r.nat_event,
                **lea.time_pair(
                    r.flow_start, r.arrived_at, r.window_start, gap_minutes=gap_minutes
                ),
            }
        )
    return out


async def _permanent_addresses(
    db: AsyncSession, subscriber_ids: list[str]
) -> dict[str, str | None]:
    from .compliance_models import IspSubscriberKyc

    ids = [uuid.UUID(s) for s in subscriber_ids if s]
    if not ids:
        return {}
    return {
        str(sid): addr
        for sid, addr in (
            await db.execute(
                select(
                    IspSubscriberKyc.subscriber_id, IspSubscriberKyc.permanent_address
                ).where(
                    IspSubscriberKyc.subscriber_id.in_(ids),
                    IspSubscriberKyc.is_deleted.is_(False),
                )
            )
        ).all()
    }


async def build_report(
    isp: IspContext,
    body: LeaTraceRequest,
    *,
    ipdr: IpdrService,
    service: IspComplianceService,
    db: AsyncSession,
    actor_name: str | None,
) -> dict[str, Any]:
    q = _query(body)
    data = await _lookup(isp, q, body.isp_customer_id, ipdr, service)
    if body.isp_customer_id is not None:
        org_ids = [body.isp_customer_id]
    else:
        org_ids = await isp.child_ids()
    routers = {r.id: r.name for r in await service.routers_of(org_ids)}
    nat_rows = await _nat_rows(db, q, routers, gap_minutes=body.gap_minutes)
    candidates = len(
        {
            (m["record"].get("organization_id"), m["record"].get("user_id"))
            for m in data["matches"]
        }
    )
    perm = await _permanent_addresses(
        db, [(m["subscriber"] or {}).get("subscriber_id") for m in data["matches"]]
    )
    matches = []
    for i, m in enumerate(data["matches"], start=1):
        r, s = m["record"], m["subscriber"] or {}
        rid = r.get("router_id")
        matches.append(
            {
                "candidate": f"{i} of {len(data['matches'])}",
                "confidence": lea.confidence(
                    data["verdict"], r.get("nat_source"), candidates
                ),
                "customer_name": m.get("customer_name"),
                "user_id": r.get("user_id"),
                "mac": r.get("mac"),
                "router_name": routers.get(uuid.UUID(rid)) if rid else None,
                # Hotspot sessions record no interface.
                "interface": None,
                "private_ip": r.get("src_ip"),
                "private_port": r.get("src_port"),
                "public_ip": r.get("nat_ip"),
                "public_port": r.get("nat_port"),
                "dst_ip": r.get("dst_ip"),
                "dst_port": r.get("dst_port"),
                "nat_source": r.get("nat_source"),
                "lease_start_ist": lea.ist(_dt(r.get("alloc_start"))),
                "lease_end_ist": lea.ist(_dt(r.get("alloc_end"))),
                **lea.time_pair(
                    _dt(r.get("ts")) if r.get("ts_source") == "flow" else None,
                    None,
                    _dt(r.get("window_start")),
                    gap_minutes=body.gap_minutes,
                ),
                "subscriber_id": s.get("subscriber_id"),
                "circuit_id": s.get("circuit_id"),
                "name": s.get("name") or r.get("name"),
                "phone": s.get("phone") or r.get("phone"),
                "email": s.get("email") or r.get("email"),
                "installation_address": s.get("address"),
                "permanent_address": perm.get(s.get("subscriber_id") or ""),
                "id_proof_type": s.get("id_proof_type"),
                # Aadhaar: last 4 only, as stored (J6).
                "id_number_masked": s.get("id_number_masked"),
                "caf_number": s.get("caf_number"),
                "caf_pdf": (
                    f"/api/v1/isp/caf/subscribers/{s['subscriber_id']}/caf.pdf"
                    if s.get("subscriber_id")
                    else None
                ),
            }
        )
    qq = data["query"]
    return {
        "lea_reference": body.lea_reference,
        "reason": body.reason,
        "generated_at_ist": lea.ist(datetime.now(UTC)),
        "generated_by": actor_name,
        "query": {
            **qq,
            "at_ist": lea.ist(q.at),
            "window_start_ist": lea.ist(q.since),
            "window_end_ist": lea.ist(q.until),
        },
        "verdict": data["verdict"],
        "nat_data_in_window": data["nat_data_in_window"],
        "public_ip_is_router_wan": data["public_ip_is_router_wan"],
        "gap_minutes": body.gap_minutes,
        "nat_rows": nat_rows,
        "matches": matches,
        "time_basis": (
            "Event time is the router's own timestamp; receipt time is when the "
            "platform received the record. They are never substituted for each "
            "other. Rows where receipt lags the event by more than "
            f"{body.gap_minutes} min are flagged."
        ),
    }


@ipdr_lea_router.post("/lea-trace", dependencies=_ON + isp_guards(ISP_IPDR_EXPORT))
async def lea_trace(
    request: Request,
    body: LeaTraceRequest,
    isp: IspContext = Depends(RequireIspPartner),
    ipdr: IpdrService = Depends(get_ipdr_service),
    service: IspComplianceService = Depends(get_compliance_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    db: AsyncSession = Depends(get_db_session),
) -> Any:
    if isp.role_slug not in UNCONFINABLE_ROLES:
        raise IspLeaOwnerAdminOnlyError()
    user = await isp.repository.get_user(isp.user_id)
    actor = " ".join(
        x
        for x in (getattr(user, "first_name", None), getattr(user, "last_name", None))
        if x
    ) or getattr(user, "email", None)
    report = await build_report(
        isp, body, ipdr=ipdr, service=service, db=db, actor_name=actor
    )
    await _audit(
        audit,
        isp,
        AUDIT_LEA_TRACE,
        "Reverse-IP trace report",
        {
            "lea_reference": body.lea_reference,
            "reason": body.reason,
            "format": body.format,
            "query": report["query"],
            "verdict": report["verdict"],
            "matches": len(report["matches"]),
            "nat_rows": len(report["nat_rows"]),
        },
    )
    await db.commit()
    if body.format == "json":
        return ok(request, report, "Reverse-IP trace")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    safe_ref = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in body.lea_reference
    )[:40]
    if body.format == "pdf":
        content, media, ext = lea.render_pdf(report), "application/pdf", "pdf"
    else:
        content = lea.render_xlsx(report)
        media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ext = "xlsx"
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": (
                f'attachment; filename="ip-trace-{safe_ref}-{stamp}.{ext}"'
            ),
            "Cache-Control": "no-store",
        },
    )


@ipdr_lea_router.get("/retention", dependencies=_ON + isp_guards(ISP_IPDR_READ))
async def retention(
    request: Request,
    gap_days: int = Query(default=90, ge=1, le=730),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.guest.models import GuestSession
    from app.domains.router_provisioning.models import RouterHealthSnapshot
    from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord as F

    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
        org_ids = [isp_customer_id]
    else:
        org_ids = await isp.child_ids()
    routers = list(await service.routers_of(org_ids))
    now = datetime.now(UTC)
    ids = [r.id for r in routers]
    oldest_nat: dict[uuid.UUID, datetime] = {}
    oldest_sess: dict[uuid.UUID, datetime] = {}
    nat_days: dict[uuid.UUID, set[date]] = {}
    up_days: dict[uuid.UUID, set[date]] = {}
    until = now.astimezone(lea.IST).date()
    since = until - timedelta(days=gap_days - 1)
    since_utc = datetime.combine(since, datetime.min.time(), tzinfo=lea.IST).astimezone(
        UTC
    )
    if ids:
        oldest_nat = dict(
            (
                await db.execute(
                    select(F.router_id, func.min(F.window_start))
                    .where(F.router_id.in_(ids), F.nat_src_address.is_not(None))
                    .group_by(F.router_id)
                )
            ).all()
        )
        oldest_sess = dict(
            (
                await db.execute(
                    select(GuestSession.router_id, func.min(GuestSession.started_at))
                    .where(GuestSession.router_id.in_(ids))
                    .group_by(GuestSession.router_id)
                )
            ).all()
        )
        day = func.date(func.timezone("Asia/Kolkata", F.window_start))
        for rid, d in (
            await db.execute(
                select(F.router_id, day)
                .where(
                    F.router_id.in_(ids),
                    F.nat_src_address.is_not(None),
                    F.window_start >= since_utc,
                )
                .group_by(F.router_id, day)
            )
        ).all():
            nat_days.setdefault(rid, set()).add(d)
        hday = func.date(
            func.timezone("Asia/Kolkata", RouterHealthSnapshot.recorded_at)
        )
        for rid, d in (
            await db.execute(
                select(RouterHealthSnapshot.router_id, hday)
                .where(
                    RouterHealthSnapshot.router_id.in_(ids),
                    RouterHealthSnapshot.recorded_at >= since_utc,
                )
                .group_by(RouterHealthSnapshot.router_id, hday)
            )
        ).all():
            up_days.setdefault(rid, set()).add(d)
    items = []
    for r in routers:
        gaps = lea.zero_row_days(
            up_days.get(r.id, set()),
            nat_days.get(r.id, set()),
            since=since,
            until=until,
        )
        items.append(
            {
                "isp_router_id": str(r.id),
                "router_name": r.name,
                "isp_customer_id": str(r.organization_id),
                **lea.retention_row(
                    oldest_nat=oldest_nat.get(r.id),
                    oldest_session=oldest_sess.get(r.id),
                    now=now,
                    gaps=gaps,
                ),
            }
        )
    return ok(
        request,
        {
            "as_of_ist": lea.ist(now),
            "target_days": lea.RETENTION_TARGET_DAYS,
            "gap_window": {"from": since.isoformat(), "to": until.isoformat()},
            "never_pruned": list(lea.NEVER_PRUNED),
            "up_basis": (
                "A day counts as up when the router sent at least one health snapshot."
            ),
            "routers": items,
        },
        "IPDR retention",
    )


@ipdr_lea_router.get(
    "/ipdr-field-coverage", dependencies=_ON + isp_guards(ISP_IPDR_READ)
)
async def ipdr_field_coverage(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    return ok(
        request,
        {
            "fields": list(lea.FIELD_COVERAGE),
            "note": (
                "Fields marked partial or not_collected are reported as missing in "
                "exports; nothing is filled in or inferred."
            ),
        },
        "IPDR field coverage",
    )


__all__ = ["build_report", "get_ipdr_lea_settings", "ipdr_lea_router"]

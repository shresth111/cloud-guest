"""ISP reports (API_CONTRACT §4.10).

Every query runs over an explicit customer id list; an ISP with no
customers (or a confined user with none) gets zeros, never platform totals.
``availability_percentage`` is ``null`` for every router: the platform has no
per-router availability series over a date range today (monitoring's only
availability figure is platform-wide health checks), and the contract says
never estimate.
"""

from __future__ import annotations

import csv
import io
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.domains.analytics.constants import ExportFormat
from app.domains.analytics.export import render_report
from app.domains.analytics.report_types import ReportPayload, ReportSection
from app.domains.guest.models import GuestSession
from app.domains.location.enums import LocationStatus
from app.domains.organization.enums import OrganizationStatus
from app.domains.router.enums import RouterStatus

from .constants import REPORT_MAX_RANGE_DAYS
from .dependencies import IspContext
from .exceptions import IspBadRequestError, IspRangeTooLongError
from .repository import require_ids
from .scoping import IspScope
from .service import PENDING_STATUSES, zone_of
from .views import cpe_online

SECTIONS = ("portfolio", "guest_activity", "usage_by_customer", "tr069")


def resolve_range(
    since: datetime | None, until: datetime | None, *, now: datetime | None = None
) -> tuple[datetime, datetime]:
    now = now or datetime.now(UTC)
    until = until or now
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    since = since or (until - timedelta(days=30))
    if since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    if since >= until:
        raise IspBadRequestError("since must be before until", field="since")
    if until - since > timedelta(days=REPORT_MAX_RANGE_DAYS):
        raise IspRangeTooLongError()
    return since, until


class IspReportsService:
    def __init__(self, repository: Any, *, clock: Any = None) -> None:
        self.repository = repository
        self._clock = clock or (lambda: datetime.now(UTC))

    async def _session_rows(
        self, ids: list[uuid.UUID], since: datetime, until: datetime, tz: str
    ) -> dict[str, Any]:
        ids = require_ids(ids)
        session = self.repository.session
        if not ids:
            return {"per_org": {}, "by_day": [], "totals": (0, 0, None)}
        in_range = [
            GuestSession.organization_id.in_(ids),
            GuestSession.started_at >= since,
            GuestSession.started_at < until,
            GuestSession.is_deleted.is_(False),
        ]
        per_org = {
            r[0]: (int(r[1]), int(r[2]), int(r[3] or 0), int(r[4] or 0))
            for r in (
                await session.execute(
                    select(
                        GuestSession.organization_id,
                        func.count(),
                        func.count(func.distinct(GuestSession.guest_id)),
                        func.sum(GuestSession.bytes_uploaded),
                        func.sum(GuestSession.bytes_downloaded),
                    )
                    .where(*in_range)
                    .group_by(GuestSession.organization_id)
                )
            ).all()
        }
        day = func.date(func.timezone(tz, GuestSession.started_at)).label("day")
        by_day = [
            {
                "day": d.isoformat() if hasattr(d, "isoformat") else str(d),
                "logins": int(n),
                "unique_guests": int(u),
                "bytes": int(b or 0),
            }
            for d, n, u, b in (
                await session.execute(
                    select(
                        day,
                        func.count(),
                        func.count(func.distinct(GuestSession.guest_id)),
                        func.sum(
                            GuestSession.bytes_uploaded + GuestSession.bytes_downloaded
                        ),
                    )
                    .where(*in_range)
                    .group_by(day)
                    .order_by(day)
                )
            ).all()
        ]
        logins, unique, avg_seconds = (
            await session.execute(
                select(
                    func.count(),
                    func.count(func.distinct(GuestSession.guest_id)),
                    func.avg(
                        func.extract(
                            "epoch", GuestSession.ended_at - GuestSession.started_at
                        )
                    ).filter(GuestSession.ended_at.is_not(None)),
                ).where(*in_range)
            )
        ).one()
        return {
            "per_org": per_org,
            "by_day": by_day,
            "totals": (int(logins), int(unique), avg_seconds),
        }

    async def summary(
        self,
        isp: IspContext,
        *,
        since: datetime | None,
        until: datetime | None,
        isp_customer_id: uuid.UUID | None,
    ) -> dict:
        since, until = resolve_range(since, until, now=self._clock())
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        tz = isp.organization.timezone or "Asia/Kolkata"
        zone_of(tz)

        orgs = await self.repository.organizations_by_id(ids)
        locations = await self.repository.locations_for_organizations(ids)
        routers = await self.repository.routers_for_organizations(ids)
        sessions = await self._session_rows(ids, since, until, tz)
        devices = [
            d
            for d in await self.repository.cpes_for_isp(isp.isp_org_id)
            if d.customer_organization_id in orgs
            or (
                d.customer_organization_id is None
                and isp_customer_id is None
                and isp.confined_customer_ids is None
            )
        ]
        now = self._clock()

        logins, unique, avg_seconds = sessions["totals"]
        usage = []
        for org_id in ids:
            org = orgs.get(org_id)
            if org is None:
                continue
            n, u, up, down = sessions["per_org"].get(org_id, (0, 0, 0, 0))
            usage.append(
                {
                    "isp_customer_id": str(org_id),
                    "name": org.name,
                    "logins": n,
                    "unique_guests": u,
                    "bytes_up": up,
                    "bytes_down": down,
                    "bytes_total": up + down,
                }
            )
        statuses = Counter(o.status for o in orgs.values())
        by_model: dict[tuple, dict] = {}
        for d in devices:
            key = (d.manufacturer, d.model, d.software_version)
            entry = by_model.setdefault(
                key,
                {
                    "manufacturer": d.manufacturer,
                    "model": d.model,
                    "software_version": d.software_version,
                    "count": 0,
                    "online": 0,
                },
            )
            entry["count"] += 1
            entry["online"] += int(cpe_online(d, now=now))
        online = sum(1 for d in devices if cpe_online(d, now=now))
        router_names = {o.id: o.name for o in orgs.values()}
        return {
            "since": since.isoformat(),
            "until": until.isoformat(),
            "timezone": tz,
            "portfolio": {
                "customers": {
                    "active": statuses.get(OrganizationStatus.ACTIVE.value, 0),
                    "suspended": statuses.get(OrganizationStatus.SUSPENDED.value, 0),
                },
                "locations": {
                    "active": sum(
                        1 for x in locations if x.status == LocationStatus.ACTIVE.value
                    ),
                    "suspended": sum(
                        1
                        for x in locations
                        if x.status == LocationStatus.SUSPENDED.value
                    ),
                },
                "routers": {
                    "online": sum(
                        1 for r in routers if r.status == RouterStatus.ONLINE.value
                    ),
                    "offline": sum(
                        1 for r in routers if r.status == RouterStatus.OFFLINE.value
                    ),
                    "pending": sum(1 for r in routers if r.status in PENDING_STATUSES),
                },
                "router_availability": [
                    {
                        "isp_router_id": str(r.id),
                        "name": r.name,
                        "customer_name": router_names.get(r.organization_id),
                        "availability_percentage": None,
                    }
                    for r in sorted(routers, key=lambda r: (r.name, str(r.id)))
                ],
            },
            "guest_activity": {
                "logins": logins,
                "unique_guests": unique,
                "avg_session_minutes": (
                    round(float(avg_seconds) / 60, 1)
                    if avg_seconds is not None
                    else None
                ),
                "by_day": sessions["by_day"],
            },
            "usage_by_customer": usage,
            "top_customers": [
                {
                    "isp_customer_id": u["isp_customer_id"],
                    "name": u["name"],
                    "bytes_total": u["bytes_total"],
                }
                for u in sorted(usage, key=lambda u: (-u["bytes_total"], u["name"]))[
                    :10
                ]
            ],
            "tr069": {
                "total": len(devices),
                "online": online,
                "offline": len(devices) - online,
                "unassigned": sum(
                    1 for d in devices if d.customer_organization_id is None
                ),
                "by_model": sorted(
                    by_model.values(),
                    key=lambda e: (
                        -e["count"],
                        str(e["model"]),
                        str(e["software_version"]),
                    ),
                ),
            },
        }


def _rows_for(section: str, report: dict) -> tuple[list[str], list[list[Any]]]:
    if section == "portfolio":
        p = report["portfolio"]
        header = ["metric", "value"]
        rows: list[list[Any]] = [
            ["customers_active", p["customers"]["active"]],
            ["customers_suspended", p["customers"]["suspended"]],
            ["locations_active", p["locations"]["active"]],
            ["locations_suspended", p["locations"]["suspended"]],
            ["routers_online", p["routers"]["online"]],
            ["routers_offline", p["routers"]["offline"]],
            ["routers_pending", p["routers"]["pending"]],
        ]
        rows += [
            [
                f"availability:{r['customer_name']}:{r['name']}",
                "not measured"
                if r["availability_percentage"] is None
                else r["availability_percentage"],
            ]
            for r in p["router_availability"]
        ]
        return header, rows
    if section == "guest_activity":
        header = ["day", "logins", "unique_guests", "bytes"]
        return header, [
            [d["day"], d["logins"], d["unique_guests"], d["bytes"]]
            for d in report["guest_activity"]["by_day"]
        ]
    if section == "usage_by_customer":
        header = [
            "customer",
            "logins",
            "unique_guests",
            "bytes_up",
            "bytes_down",
            "bytes_total",
        ]
        return header, [
            [
                u["name"],
                u["logins"],
                u["unique_guests"],
                u["bytes_up"],
                u["bytes_down"],
                u["bytes_total"],
            ]
            for u in report["usage_by_customer"]
        ]
    if section == "tr069":
        header = ["manufacturer", "model", "software_version", "count", "online"]
        return header, [
            [
                m["manufacturer"],
                m["model"],
                m["software_version"],
                m["count"],
                m["online"],
            ]
            for m in report["tr069"]["by_model"]
        ]
    raise IspBadRequestError("unknown section", field="section")


def _safe(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text and text[0] in "=+-@\t\r" else text


def render_csv(section: str, report: dict) -> bytes:
    header, rows = _rows_for(section, report)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow([_safe(v) for v in row])
    return buffer.getvalue().encode("utf-8")


def render_pdf(report: dict, *, title: str) -> bytes:
    """Every section through the existing analytics PDF renderer."""
    sections = []
    for section in SECTIONS:
        header, rows = _rows_for(section, report)
        sections.append(
            ReportSection(
                key=section,
                title=section.replace("_", " ").title(),
                data={"rows": [dict(zip(header, row, strict=True)) for row in rows]},
            )
        )
    payload = ReportPayload(
        report_type="isp_partner",
        title=title,
        generated_at=datetime.now(UTC).isoformat(),
        organization_id=None,
        location_id=None,
        period_start=report["since"],
        period_end=report["until"],
        sections=sections,
    )
    return render_report(payload, ExportFormat.PDF).content

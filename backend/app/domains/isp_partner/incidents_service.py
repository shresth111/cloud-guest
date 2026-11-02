"""INCIDENTS-1 service.

* **Affected subscribers** come only from existing data:
  - router: subscribers with any hotspot session (via their guest) or PPPoE
    session on that router, ever -- the DASH-1 "router filter" rule;
  - fiber node: JAZE-6 ``IspFiberService.downstream`` (every port under it);
  - zone: subscribers whose own zone is in the ZONE-1 subtree, or who have
    none and whose customer's profile zone is (the ZONE-1 scope rule).
  The list is snapshotted ISP-wide when the incident is opened (and on an
  explicit refresh); every read shows a caller only the subscribers of the
  customers they can see.
* **Grace** calls the JAZE-1 ``IspSubscriber360Service.grace`` once per
  subscriber, each in its own SAVEPOINT, only after the incident is resolved,
  dry-run first. Once per (incident, subscriber), ever.
* **Broadcast** goes only through the JAZE-4 WhatsApp automation path
  (``automation._WhatsappRun``: the ISP's own verified sender, its approved
  template mapped for ``outage`` / ``restored``, opt-in and exclusions
  honoured, one dedupe key per subscriber). When the flag, the ISP's
  automation switch, the sender or the template is missing, nothing is sent:
  the answer carries share links and the CSV instead.
* **Network health** = routers up / (up + down) from ``routers.status`` (the
  same reading J14 alerts use); pending routers are reported but not counted.
"""

from __future__ import annotations

import csv
import io
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

from sqlalchemy import func, select, text

from .exceptions import IspBadRequestError, IspError
from .incidents_config import (
    IspIncidentNotFoundError,
    IspIncidentStateError,
)
from .incidents_models import IspIncident, IspIncidentEvent, IspIncidentSubscriber
from .plans_models import IspSubscriber
from .scoping import IspScope

STATUSES = ("investigating", "identified", "resolved")
SEVERITIES = ("minor", "major", "critical")
SCOPE_KINDS = ("router", "fiber_node", "zone")
RFO_REASONS = ("fiber_cut", "power_olt", "cpe_fault", "upstream", "other")
RFO_LABEL = {
    "fiber_cut": "Fiber cut",
    "power_olt": "Power / OLT",
    "cpe_fault": "Customer device fault",
    "upstream": "Upstream provider",
    "other": "Other",
    # SMALL-5: set only by the auto-incident job (not offered to staff)
    "auto_restored": "Power/link restored – auto",
}
NO_MATCH = uuid.UUID(int=0)


def _iso(v: Any) -> Any:
    return v.isoformat() if v is not None and hasattr(v, "isoformat") else v


def has_key(isp: Any, key: str) -> bool:
    from .rbac_roles import ROLES_BY_SLUG

    role = ROLES_BY_SLUG.get(getattr(isp, "role_slug", ""))
    return role is not None and key in role.permission_keys


def sub_label(s: Any) -> str:
    name = " ".join(p for p in (s.first_name, s.last_name) if p).strip()
    return name or s.display_name or s.identifier


def outage_text(isp_name: str, name: str, area: str, since: str) -> str:
    return (
        f"Dear {name}, internet service in {area} is down since {since}. "
        f"Our team is working on it and we will update you. - {isp_name}"
    )


def restored_text(isp_name: str, name: str, area: str, at: str) -> str:
    return (
        f"Dear {name}, internet service in {area} is back since {at}. "
        f"Sorry for the trouble. - {isp_name}"
    )


def default_grace_hours(started: datetime, resolved: datetime | None) -> int:
    """Outage length rounded up to whole hours, 1..168 (the JAZE-1 limits)."""
    if resolved is None:
        return 1
    secs = max(0.0, (resolved - started).total_seconds())
    return max(1, min(168, int(-(-secs // 3600))))


@asynccontextmanager
async def _without_zone_scope(session: Any):  # noqa: ANN202
    """The snapshot is ISP-wide; lift ZONE-1's per-request loader criteria
    for the duration and put them back."""
    from .zones_scope import _INFO_KEY

    saved = session.info.pop(_INFO_KEY, None)
    try:
        yield
    finally:
        if saved is not None:
            session.info[_INFO_KEY] = saved


class IspIncidentsService:
    def __init__(self, *, session: Any, audit: Any = None, clock: Any = None) -> None:
        self.session = session
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return self._clock()

    def tz(self, isp: Any) -> ZoneInfo:
        return ZoneInfo(isp.organization.timezone or "Asia/Kolkata")

    def local(self, isp: Any, at: datetime | None) -> str:
        return at.astimezone(self.tz(isp)).strftime("%d %b %Y, %H:%M") if at else ""

    async def _audit(self, isp: Any, action: str, entity_id: Any, **meta) -> None:  # noqa: ANN003
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type="isp_incident",
            entity_id=entity_id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **{
                    k: (str(v) if isinstance(v, uuid.UUID) else v)
                    for k, v in meta.items()
                },
            },
            organization_id=isp.isp_org_id,
            location_id=None,
        )

    # ------------------------------------------------------------------
    # scope targets + affected subscribers
    # ------------------------------------------------------------------
    async def target(
        self,
        isp: Any,
        kind: str,
        *,
        isp_router_id: uuid.UUID | None,
        fiber_node_id: uuid.UUID | None,
        zone_id: uuid.UUID | None,
    ) -> dict:
        """The one thing the incident is about, checked against the caller's
        scope (404 otherwise)."""
        given = [x for x in (isp_router_id, fiber_node_id, zone_id) if x]
        if len(given) != 1:
            raise IspBadRequestError(
                "Pick exactly one router, fiber node or zone", field="scope_kind"
            )
        if kind == "router" and isp_router_id:
            r = await IspScope.assert_router(isp, isp_router_id)
            return {
                "router_id": r.id,
                "customer_id": r.organization_id,
                "label": f"Router {r.name}",
            }
        if kind == "fiber_node" and fiber_node_id:
            from .fiber_service import IspFiberService, get_isp_fiber_settings

            if not get_isp_fiber_settings().enabled:
                raise IspBadRequestError(
                    "The fiber registry is not switched on", field="fiber_node_id"
                )
            n = await IspFiberService(self.session)._node(isp, fiber_node_id)
            return {
                "fiber_node_id": n.id,
                "customer_id": n.customer_organization_id,
                "label": f"{n.kind.upper()} {n.name}",
            }
        if kind == "zone" and zone_id:
            from .billing_models import IspZone
            from .exceptions import IspZoneNotFoundError

            z = await self.session.get(IspZone, zone_id)
            if z is None or z.is_deleted or z.isp_organization_id != isp.isp_org_id:
                raise IspZoneNotFoundError()
            return {"zone_id": z.id, "customer_id": None, "label": f"Zone {z.name}"}
        raise IspBadRequestError(
            "The id does not match the scope kind",
            field="scope_kind",
            reason="ISP_QUERY_INVALID",
        )

    async def compute_affected(self, isp: Any, t: dict) -> list[dict]:
        """ISP-wide (not confined, not zone-narrowed): who sits behind it."""
        wide = replace(isp, confined_customer_ids=None, _child_ids=None)
        async with _without_zone_scope(self.session):
            if "router_id" in t:
                return await self._on_router(isp, t["router_id"])
            if "fiber_node_id" in t:
                from .fiber_service import IspFiberService

                d = await IspFiberService(self.session).downstream(
                    wide, t["fiber_node_id"]
                )
                return [
                    {
                        "subscriber_id": uuid.UUID(str(s["subscriber_id"])),
                        "customer_id": uuid.UUID(str(s["isp_customer_id"])),
                        "source": "fiber",
                        "node_name": s.get("node_name"),
                        "port_no": s.get("port_no"),
                    }
                    for s in d["subscribers"]
                ]
            return await self._in_zone(isp, t["zone_id"])

    async def _on_router(self, isp: Any, router_id: uuid.UUID) -> list[dict]:
        from app.domains.guest.models import GuestSession

        from .pppoe_models import IspPppoeSession

        guests = select(GuestSession.guest_id).where(
            GuestSession.router_id == router_id
        )
        pppoe = select(IspPppoeSession.subscriber_id).where(
            IspPppoeSession.router_id == router_id,
            IspPppoeSession.subscriber_id.is_not(None),
        )
        rows = (
            (
                await self.session.execute(
                    select(IspSubscriber).where(
                        IspSubscriber.isp_organization_id == isp.isp_org_id,
                        IspSubscriber.is_deleted.is_(False),
                        IspSubscriber.guest_id.in_(guests)
                        | IspSubscriber.id.in_(pppoe),
                    )
                )
            )
            .scalars()
            .all()
        )
        return [
            {
                "subscriber_id": s.id,
                "customer_id": s.customer_organization_id,
                "source": "router",
                "node_name": None,
                "port_no": None,
            }
            for s in rows
        ]

    async def _in_zone(self, isp: Any, zone_id: uuid.UUID) -> list[dict]:
        from .zones_scope import _subscriber_criteria, build_scope

        scope, _ = await build_scope(self.session, isp.isp_org_id, zone_id)
        rows = (
            (
                await self.session.execute(
                    select(IspSubscriber).where(
                        IspSubscriber.isp_organization_id == isp.isp_org_id,
                        IspSubscriber.is_deleted.is_(False),
                        _subscriber_criteria(scope),
                    )
                )
            )
            .scalars()
            .all()
        )
        return [
            {
                "subscriber_id": s.id,
                "customer_id": s.customer_organization_id,
                "source": "zone",
                "node_name": None,
                "port_no": None,
            }
            for s in rows
        ]

    async def preview(self, isp: Any, kind: str, **ids: Any) -> dict:
        t = await self.target(isp, kind, **ids)
        found = await self.compute_affected(isp, t)
        visible = set(await isp.child_ids())
        zone_ok = await self._zone_ok([f["subscriber_id"] for f in found])
        mine = [
            f
            for f in found
            if f["customer_id"] in visible
            and (zone_ok is None or f["subscriber_id"] in zone_ok)
        ]
        subs = await self._subs([f["subscriber_id"] for f in mine[:20]])
        return {
            "scope_label": t["label"],
            "affected_total": len(found),
            "affected_visible": len(mine),
            "sample": [
                {
                    "subscriber_id": str(f["subscriber_id"]),
                    "label": sub_label(subs[f["subscriber_id"]]),
                    "identifier": subs[f["subscriber_id"]].identifier,
                }
                for f in mine[:20]
                if f["subscriber_id"] in subs
            ],
        }

    async def _subs(self, ids: list) -> dict:
        if not ids:
            return {}
        async with _without_zone_scope(self.session):
            rows = (
                await self.session.execute(
                    select(IspSubscriber).where(IspSubscriber.id.in_(ids))
                )
            ).scalars()
            return {s.id: s for s in rows}

    # ------------------------------------------------------------------
    # create / read
    # ------------------------------------------------------------------
    def _event(self, isp: Any, inc: IspIncident, kind: str, **kw: Any) -> None:
        self.session.add(
            IspIncidentEvent(
                incident_id=inc.id,
                kind=kind,
                occurred_at=self.now(),
                created_by=isp.user_id,
                detail=kw.pop("detail", {}) or {},
                **kw,
            )
        )

    async def _next_number(self, isp_org_id: uuid.UUID) -> int:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
            {"k": f"isp_incident_no:{isp_org_id}"},
        )
        n = (
            await self.session.execute(
                select(func.coalesce(func.max(IspIncident.number), 0)).where(
                    IspIncident.isp_organization_id == isp_org_id
                )
            )
        ).scalar_one()
        return int(n) + 1

    async def create(self, isp: Any, data: dict) -> dict:
        t = await self.target(
            isp,
            data["scope_kind"],
            isp_router_id=data.get("isp_router_id"),
            fiber_node_id=data.get("fiber_node_id"),
            zone_id=data.get("zone_id"),
        )
        started = data.get("started_at") or self.now()
        if started > self.now() + timedelta(minutes=5):
            raise IspBadRequestError(
                "The start time is in the future", field="started_at"
            )
        found = await self.compute_affected(isp, t)
        inc = IspIncident(
            isp_organization_id=isp.isp_org_id,
            number=await self._next_number(isp.isp_org_id),
            title=data.get("title") or f"Outage: {t['label']}",
            scope_kind=data["scope_kind"],
            router_id=t.get("router_id"),
            fiber_node_id=t.get("fiber_node_id"),
            zone_id=t.get("zone_id"),
            customer_organization_id=t.get("customer_id"),
            scope_label=t["label"][:255],
            severity=data.get("severity") or "major",
            status="investigating",
            started_at=started,
            affected_count=len(found),
            created_by=isp.user_id,
        )
        self.session.add(inc)
        await self.session.flush()
        self._add_affected(inc, found)
        self._event(
            isp,
            inc,
            "created",
            status="investigating",
            body=data.get("note"),
            detail={"affected": len(found), "scope": t["label"]},
        )
        await self.session.flush()
        await self._audit(
            isp,
            "isp_incident_opened",
            inc.id,
            number=inc.number,
            scope=inc.scope_label,
            affected=len(found),
        )
        return await self.detail(isp, inc.id)

    def _add_affected(
        self, inc: IspIncident, found: list[dict], have: set | None = None
    ) -> int:
        have = have or set()
        n = 0
        for f in found:
            if f["subscriber_id"] in have:
                continue
            have.add(f["subscriber_id"])
            self.session.add(
                IspIncidentSubscriber(
                    incident_id=inc.id,
                    subscriber_id=f["subscriber_id"],
                    customer_organization_id=f["customer_id"],
                    source=f["source"],
                    node_name=(f.get("node_name") or None),
                    port_no=f.get("port_no"),
                )
            )
            n += 1
        return n

    async def _affected_rows(self, inc_ids: list) -> dict[uuid.UUID, list]:
        if not inc_ids:
            return {}
        rows = (
            (
                await self.session.execute(
                    select(IspIncidentSubscriber).where(
                        IspIncidentSubscriber.incident_id.in_(inc_ids),
                        IspIncidentSubscriber.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        out: dict[uuid.UUID, list] = {}
        for r in rows:
            out.setdefault(r.incident_id, []).append(r)
        return out

    async def _zone_ok(self, subscriber_ids: list) -> set | None:
        """P3-SWEEP: affected subscribers that pass the ZONE-1 subscriber rule
        (own zone, else the customer's zone) in a zone-scoped request; None
        when there is no zone scope. Only ever narrows."""
        from .zones_scope import zone_visible_subscribers

        return await zone_visible_subscribers(self.session, subscriber_ids)

    async def _mine(self, rows: list, visible: set) -> list:
        """Affected rows the caller may see: customer confinement (as before)
        AND, in a zone-scoped request, the subscriber's own zone."""
        zone_ok = await self._zone_ok([r.subscriber_id for r in rows])
        return [
            r
            for r in rows
            if r.customer_organization_id in visible
            and (zone_ok is None or r.subscriber_id in zone_ok)
        ]

    async def _visible(
        self, isp: Any, inc: IspIncident, affected: list, visible: set
    ) -> bool:
        if inc.isp_organization_id != isp.isp_org_id or inc.is_deleted:
            return False
        if inc.customer_organization_id is not None:
            return inc.customer_organization_id in visible
        if inc.scope_kind == "fiber_node" and isp.confined_customer_ids is None:
            return True  # shared plant: every unconfined staff member sees it
        if isp.confined_customer_ids is None:
            return True
        return bool(await self._mine(affected, visible))

    async def incident(self, isp: Any, incident_id: uuid.UUID) -> IspIncident:
        inc = await self.session.get(IspIncident, incident_id)
        if inc is None:
            raise IspIncidentNotFoundError()
        affected = (await self._affected_rows([inc.id])).get(inc.id, [])
        if not await self._visible(isp, inc, affected, set(await isp.child_ids())):
            raise IspIncidentNotFoundError()
        return inc

    def _view(self, isp: Any, inc: IspIncident, affected_visible: int) -> dict:
        end = inc.resolved_at or self.now()
        return {
            "id": str(inc.id),
            "number": inc.number,
            "code": f"INC-{inc.number:05d}",
            "title": inc.title,
            "scope_kind": inc.scope_kind,
            "scope_label": inc.scope_label,
            "isp_router_id": str(inc.router_id) if inc.router_id else None,
            "fiber_node_id": str(inc.fiber_node_id) if inc.fiber_node_id else None,
            "zone_id": str(inc.zone_id) if inc.zone_id else None,
            "isp_customer_id": str(inc.customer_organization_id)
            if inc.customer_organization_id
            else None,
            "severity": inc.severity,
            "status": inc.status,
            "started_at": _iso(inc.started_at),
            "identified_at": _iso(inc.identified_at),
            "resolved_at": _iso(inc.resolved_at),
            "duration_minutes": int((end - inc.started_at).total_seconds() // 60),
            "rfo_reason": inc.rfo_reason,
            "rfo_label": RFO_LABEL.get(inc.rfo_reason or ""),
            "rfo_note": inc.rfo_note,
            "affected_total": inc.affected_count,
            "affected_visible": affected_visible,
            "grace_hours": inc.grace_hours,
            "grace_applied_at": _iso(inc.grace_applied_at),
        }

    async def list(
        self,
        isp: Any,
        *,
        status: str | None,
        scope_kind: str | None,
        open_only: bool,
        date_from: Any,
        date_to: Any,
        page: int,
        page_size: int,
    ) -> dict:
        q = select(IspIncident).where(
            IspIncident.isp_organization_id == isp.isp_org_id,
            IspIncident.is_deleted.is_(False),
        )
        if status:
            q = q.where(IspIncident.status == status)
        if open_only:
            q = q.where(IspIncident.status != "resolved")
        if scope_kind:
            q = q.where(IspIncident.scope_kind == scope_kind)
        tz = self.tz(isp)
        if date_from:
            q = q.where(
                IspIncident.started_at
                >= datetime.combine(date_from, datetime.min.time(), tzinfo=tz)
            )
        if date_to:
            q = q.where(
                IspIncident.started_at
                < datetime.combine(
                    date_to + timedelta(days=1), datetime.min.time(), tzinfo=tz
                )
            )
        rows = (
            (await self.session.execute(q.order_by(IspIncident.started_at.desc())))
            .scalars()
            .all()
        )
        affected = await self._affected_rows([r.id for r in rows])
        visible = set(await isp.child_ids())
        items = []
        for inc in rows:
            a = affected.get(inc.id, [])
            if await self._visible(isp, inc, a, visible):
                items.append(self._view(isp, inc, len(await self._mine(a, visible))))
        resolved = [i for i in items if i["status"] == "resolved"]
        start = (page - 1) * page_size
        return {
            "items": items[start : start + page_size],
            "total": len(items),
            "page": page,
            "page_size": page_size,
            "summary": {
                "open": sum(1 for i in items if i["status"] != "resolved"),
                "resolved": len(resolved),
                "mttr_minutes": (
                    sum(i["duration_minutes"] for i in resolved) // len(resolved)
                    if resolved
                    else None
                ),
                "subscriber_minutes_lost": sum(
                    i["duration_minutes"] * i["affected_visible"] for i in resolved
                ),
            },
        }

    async def detail(self, isp: Any, incident_id: uuid.UUID) -> dict:
        inc = await self.incident(isp, incident_id)
        visible = set(await isp.child_ids())
        rows = await self._mine(
            (await self._affected_rows([inc.id])).get(inc.id, []), visible
        )
        subs = await self._subs([r.subscriber_id for r in rows])
        events = (
            (
                await self.session.execute(
                    select(IspIncidentEvent)
                    .where(IspIncidentEvent.incident_id == inc.id)
                    .order_by(IspIncidentEvent.occurred_at)
                )
            )
            .scalars()
            .all()
        )
        from .apps_common import org_names, user_names

        names = await user_names(self.session, {e.created_by for e in events})
        orgs = await org_names(self.session, {r.customer_organization_id for r in rows})
        view = self._view(isp, inc, len(rows))
        view["events"] = [
            {
                "id": str(e.id),
                "kind": e.kind,
                "status": e.status,
                "body": e.body,
                "detail": e.detail or {},
                "at": _iso(e.occurred_at),
                "actor": names.get(e.created_by),
            }
            for e in events
        ]
        view["affected"] = [
            {
                "subscriber_id": str(r.subscriber_id),
                "label": sub_label(subs[r.subscriber_id])
                if r.subscriber_id in subs
                else None,
                "identifier": subs[r.subscriber_id].identifier
                if r.subscriber_id in subs
                else None,
                "phone": subs[r.subscriber_id].phone
                if r.subscriber_id in subs
                else None,
                "status": subs[r.subscriber_id].status
                if r.subscriber_id in subs
                else None,
                "isp_customer_id": str(r.customer_organization_id),
                "customer_name": orgs.get(r.customer_organization_id),
                "source": r.source,
                "node_name": r.node_name,
                "port_no": r.port_no,
                "grace_status": r.grace_status,
                "grace_detail": r.grace_detail,
                "outage_message": r.outage_message,
                "restored_message": r.restored_message,
            }
            for r in rows
        ]
        view["suggested_grace_hours"] = default_grace_hours(
            inc.started_at, inc.resolved_at
        )
        return view

    # ------------------------------------------------------------------
    # status / notes / refresh
    # ------------------------------------------------------------------
    async def set_status(self, isp: Any, incident_id: uuid.UUID, data: dict) -> dict:
        inc = await self.incident(isp, incident_id)
        to = data["status"]
        order = {s: i for i, s in enumerate(STATUSES)}
        if order[to] <= order[inc.status]:
            raise IspIncidentStateError(
                f"An incident that is {inc.status} cannot move to {to}",
                reason="ISP_STATUS_CHANGED",
            )
        now = self.now()
        if to == "identified":
            inc.identified_at = now
        if to == "resolved":
            if not data.get("rfo_reason"):
                raise IspBadRequestError(
                    "Give the reason for outage to resolve", field="rfo_reason"
                )
            inc.resolved_at = data.get("resolved_at") or now
            if inc.resolved_at < inc.started_at or inc.resolved_at > now + timedelta(
                minutes=5
            ):
                raise IspBadRequestError(
                    "The end time must be after the start and not in the future",
                    field="resolved_at",
                )
            inc.identified_at = inc.identified_at or inc.resolved_at
        if data.get("rfo_reason"):
            inc.rfo_reason = data["rfo_reason"]
        if data.get("rfo_note"):
            inc.rfo_note = data["rfo_note"]
        inc.status = to
        inc.updated_by = isp.user_id
        self._event(
            isp,
            inc,
            "status",
            status=to,
            body=data.get("note"),
            detail={"rfo_reason": inc.rfo_reason} if to == "resolved" else {},
        )
        await self.session.flush()
        await self._audit(
            isp,
            "isp_incident_resolved" if to == "resolved" else "isp_incident_status",
            inc.id,
            number=inc.number,
            status=to,
            rfo_reason=inc.rfo_reason,
        )
        return await self.detail(isp, inc.id)

    async def add_note(self, isp: Any, incident_id: uuid.UUID, body: str) -> dict:
        inc = await self.incident(isp, incident_id)
        self._event(isp, inc, "note", body=body)
        await self.session.flush()
        return await self.detail(isp, inc.id)

    async def refresh(self, isp: Any, incident_id: uuid.UUID) -> dict:
        inc = await self.incident(isp, incident_id)
        if inc.status == "resolved":
            raise IspIncidentStateError("A resolved incident is not refreshed")
        t = {
            "router_id": inc.router_id,
            "fiber_node_id": inc.fiber_node_id,
            "zone_id": inc.zone_id,
        }
        t = {k: v for k, v in t.items() if v}
        found = await self.compute_affected(isp, t)
        have = {
            r.subscriber_id
            for r in (await self._affected_rows([inc.id])).get(inc.id, [])
        }
        added = self._add_affected(inc, found, have)
        inc.affected_count = len(have)
        self._event(isp, inc, "affected_refreshed", detail={"added": added})
        await self.session.flush()
        return await self.detail(isp, inc.id)

    # ------------------------------------------------------------------
    # grace (JAZE-1 action, per subscriber, dry run first)
    # ------------------------------------------------------------------
    async def grace(
        self, isp: Any, incident_id: uuid.UUID, *, hours: int, dry_run: bool, s360: Any
    ) -> dict:
        if not has_key(isp, "isp_subscribers.update"):
            from .exceptions import IspRoleRequiredError

            raise IspRoleRequiredError("Granting grace needs isp_subscribers.update")
        inc = await self.incident(isp, incident_id)
        if inc.status != "resolved":
            raise IspIncidentStateError("Resolve the incident before granting grace")
        visible = set(await isp.child_ids())
        rows = await self._mine(
            (await self._affected_rows([inc.id])).get(inc.id, []), visible
        )
        subs = await self._subs([r.subscriber_id for r in rows])
        plan: list[tuple[Any, str | None]] = []
        for r in rows:
            s = subs.get(r.subscriber_id)
            if r.grace_status is not None:
                reason = f"already {r.grace_status}"
            elif s is None or s.is_deleted:
                reason = "subscriber removed"
            elif s.valid_until is None or s.valid_until < inc.started_at:
                reason = "not on a valid plan during the outage"
            else:
                reason = None
            plan.append((r, reason))
        eligible = [r for r, why in plan if why is None]
        out = {
            "dry_run": dry_run,
            "hours": hours,
            "affected_visible": len(rows),
            "eligible": len(eligible),
            "skipped": [
                {"subscriber_id": str(r.subscriber_id), "reason": why}
                for r, why in plan
                if why is not None
            ][:500],
            "applied": 0,
            "failed": [],
        }
        if dry_run:
            return out
        now = self.now()
        for r in eligible:
            try:
                async with self.session.begin_nested():
                    await s360.grace(
                        isp,
                        r.subscriber_id,
                        hours=hours,
                        note=f"Outage compensation INC-{inc.number:05d}",
                    )
                r.grace_status, r.grace_detail = "applied", f"{hours} h"
                out["applied"] += 1
            except IspError as exc:
                r.grace_status, r.grace_detail = "skipped", str(exc.message)[:255]
                out["failed"].append(
                    {"subscriber_id": str(r.subscriber_id), "reason": r.grace_detail}
                )
            r.grace_at = now
        inc.grace_hours, inc.grace_applied_at = hours, now
        self._event(
            isp,
            inc,
            "grace",
            detail={
                "hours": hours,
                "applied": out["applied"],
                "skipped": len(out["failed"]) + len(out["skipped"]),
            },
        )
        await self.session.flush()
        await self._audit(
            isp,
            "isp_incident_grace",
            inc.id,
            number=inc.number,
            hours=hours,
            applied=out["applied"],
        )
        return out

    # ------------------------------------------------------------------
    # broadcast (JAZE-4 WhatsApp automation path only)
    # ------------------------------------------------------------------
    async def channel(self, isp: Any, trigger: str) -> tuple[Any, list[str]]:
        """(_WhatsappRun or None, reasons it is not available)."""
        from .automation import _whatsapp_sender, _WhatsappRun, automation_settings
        from .finance_config import get_finance_settings

        reasons = []
        if not get_finance_settings().whatsapp_automation_enabled:
            reasons.append("WhatsApp automation is not switched on for the platform")
        st = await automation_settings(self.session, isp.isp_org_id)
        if st is None or not st.whatsapp_enabled:
            reasons.append("WhatsApp automation is off in your Finance settings")
        if st is None or not (st.whatsapp_templates or {}).get(trigger):
            reasons.append(f"No approved template is mapped for '{trigger}'")
        sender = await _whatsapp_sender(self.session, isp.isp_org_id)
        if sender is None:
            reasons.append("Your WhatsApp sender is not set up and verified")
        if reasons:
            return None, reasons
        return _WhatsappRun(self.session, isp.isp_org_id, st, sender), []

    async def broadcast(
        self, isp: Any, incident_id: uuid.UUID, *, kind: str, dry_run: bool
    ) -> dict:
        from .automation import _contact_flags, _may_message, e164_in

        inc = await self.incident(isp, incident_id)
        if kind == "restored" and inc.status != "resolved":
            raise IspIncidentStateError(
                "Send 'restored' after the incident is resolved"
            )
        if kind == "outage" and inc.status == "resolved":
            raise IspIncidentStateError("The incident is already resolved")
        run, reasons = await self.channel(isp, kind)
        visible = set(await isp.child_ids())
        rows = await self._mine(
            (await self._affected_rows([inc.id])).get(inc.id, []), visible
        )
        subs = await self._subs([r.subscriber_id for r in rows])
        flags = await _contact_flags(self.session, isp.isp_org_id)
        col = "outage_message" if kind == "outage" else "restored_message"
        when = self.local(isp, inc.started_at if kind == "outage" else inc.resolved_at)
        area = inc.scope_label
        counts = {"recipients": 0, "no_consent": 0, "no_phone": 0, "already": 0}
        targets = []
        for r in rows:
            s = subs.get(r.subscriber_id)
            if s is None or s.status != "active":
                continue
            if getattr(r, col) == "sent":
                counts["already"] += 1
                continue
            if e164_in(s.phone) is None:
                counts["no_phone"] += 1
                continue
            if not _may_message(flags, "subscriber", s):
                counts["no_consent"] += 1
                continue
            counts["recipients"] += 1
            targets.append((r, s))
        name_of = isp.organization.name
        message = (outage_text if kind == "outage" else restored_text)(
            name_of, "{name}", area, when
        )
        out = {
            "kind": kind,
            "mode": "whatsapp" if run else "share",
            "dry_run": dry_run,
            "unavailable_reasons": reasons,
            **counts,
            "message": message,
            "csv_path": f"/isp/incidents/{inc.id}/affected.csv",
            "sent": 0,
            "failed": 0,
            "share": [],
        }
        if run is None:
            # Nothing is ever sent from here without the automation path.
            out["share"] = [
                {
                    "subscriber_id": str(s.id),
                    "label": sub_label(s),
                    "phone": s.phone,
                    "whatsapp_url": "https://wa.me/"
                    + (e164_in(s.phone) or "").lstrip("+")
                    + "?text="
                    + quote(message.replace("{name}", sub_label(s))),
                }
                for _r, s in targets[:500]
            ]
            return out
        if dry_run:
            return out
        for r, s in targets:
            before = (run.sent, run.failed, run.skipped)
            await run.send(
                kind,
                s.phone,
                [sub_label(s), area, when],
                dedupe_key=f"incident:{inc.id}:{kind}:{s.id}",
                summary=f"INC-{inc.number:05d} {kind}: {area}",
                customer_id=s.customer_organization_id,
                subscriber_id=s.id,
            )
            if run.sent > before[0]:
                setattr(r, col, "sent")
            elif run.failed > before[1]:
                setattr(r, col, "failed")
        out["sent"], out["failed"] = run.sent, run.failed
        self._event(
            isp,
            inc,
            "broadcast",
            detail={"kind": kind, "sent": run.sent, "failed": run.failed},
        )
        await self.session.flush()
        await self._audit(
            isp,
            "isp_incident_broadcast",
            inc.id,
            number=inc.number,
            kind=kind,
            sent=run.sent,
            failed=run.failed,
        )
        return out

    async def affected_csv(self, isp: Any, incident_id: uuid.UUID) -> tuple[str, str]:
        d = await self.detail(isp, incident_id)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "name",
                "username",
                "phone",
                "customer",
                "status",
                "found_by",
                "node",
                "port",
                "grace",
                "outage_message",
                "restored_message",
            ]
        )
        for a in d["affected"]:
            w.writerow(
                [
                    _csv_safe(a["label"]),
                    _csv_safe(a["identifier"]),
                    _csv_safe(a["phone"]),
                    _csv_safe(a["customer_name"]),
                    a["status"] or "",
                    a["source"],
                    _csv_safe(a["node_name"]),
                    a["port_no"] if a["port_no"] is not None else "",
                    a["grace_status"] or "",
                    a["outage_message"] or "",
                    a["restored_message"] or "",
                ]
            )
        await self._audit(
            isp,
            "isp_incident_affected_exported",
            uuid.UUID(d["id"]),
            rows=len(d["affected"]),
        )
        return buf.getvalue(), f"{d['code']}-affected.csv"

    # ------------------------------------------------------------------
    # network health headline
    # ------------------------------------------------------------------
    async def health(self, isp: Any) -> dict:
        from app.domains.router.models import Router
        from app.domains.router.vendor_capabilities import is_controller_managed_row

        children = await isp.child_ids()
        counts: dict[str, int] = {}
        controller = 0
        if children:
            # Whole rows, not a GROUP BY: whether a row is controller-managed
            # is decided from its evidence (is_controller_managed_row), which
            # SQL on the vendor label alone cannot do. Small per ISP.
            for r in (
                await self.session.execute(
                    select(Router).where(
                        Router.organization_id.in_(children),
                        Router.is_deleted.is_(False),
                    )
                )
            ).scalars():
                if is_controller_managed_row(r):
                    # CI-INTEG: an Omada / Aruba controller row has no agent,
                    # so its stored status says nothing about the venue.
                    controller += 1
                    continue
                counts[r.status] = counts.get(r.status, 0) + 1
        up = int(counts.get("online", 0))
        down = int(counts.get("offline", 0))
        total = sum(int(v) for v in counts.values())
        open_ = await self.list(
            isp,
            status=None,
            scope_kind=None,
            open_only=True,
            date_from=None,
            date_to=None,
            page=1,
            page_size=1,
        )
        return {
            "routers_total": total,
            "routers_up": up,
            "routers_down": down,
            "routers_not_reporting": total - up - down,
            "routers_controller_managed": controller,
            "health_percent": round(100 * up / (up + down), 1) if up + down else None,
            "basis": (
                "Routers online / (online + offline), from each router's last "
                "status. Routers that never reported (pending setup) are not "
                "counted. Venues run through a vendor controller (Omada, Aruba "
                "Instant On) are listed apart and not counted either."
            ),
            "open_incidents": open_["summary"]["open"],
            "as_of": _iso(self.now()),
        }


def _csv_safe(v: Any) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


__all__ = ["IspIncidentsService", "has_key"]

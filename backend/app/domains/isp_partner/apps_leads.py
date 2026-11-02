"""J16 leads: enquiry -> feasibility -> install task -> subscriber.

* A lead may start without a customer (a prospect in a new area). Such
  leads are visible to unconfined staff only. Once the ISP decides which
  customer will serve it, ``isp_customer_id`` is set (checked by
  ``IspScope``), and confined staff covering that customer see it.
* ``converted`` is reached only through ``convert``, which creates the
  subscriber through the existing ``IspPlansService.create_subscriber``
  (unchanged) and links it. ``dropped`` needs a reason and can be reopened.
* ``schedule_install`` creates an install field task for the lead and moves
  it to ``install_scheduled``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select

from .apps_common import (
    IspAppsInvalidError,
    IspAppsNotFoundError,
    LeadStatus,
    assert_assignee,
    fmt_number,
    next_number,
    org_names,
    user_names,
)
from .apps_models import IspFieldTask, IspLead
from .apps_tasks import FieldTaskService
from .scoping import IspScope

TERMINAL = frozenset({LeadStatus.CONVERTED})
#: statuses a plain PATCH may set ("converted" only via convert)
SETTABLE = frozenset(s.value for s in LeadStatus) - {LeadStatus.CONVERTED.value}


def _now() -> datetime:
    return datetime.now(UTC)


def check_lead_status(current: str, target: str, *, dropped_reason: str | None) -> None:
    if current == target:
        return
    if current in TERMINAL:
        raise IspAppsInvalidError("A converted lead cannot change status")
    if target not in SETTABLE:
        raise IspAppsInvalidError("Use convert to turn a lead into a subscriber")
    if target == LeadStatus.DROPPED and not dropped_reason:
        raise IspAppsInvalidError("Say why the lead is dropped")


class LeadService:
    def __init__(self, session: Any, plans_service: Any | None = None) -> None:
        self.session = session
        self.plans_service = plans_service

    async def _visible(self, isp: Any, lead: Any) -> bool:
        if (
            lead is None
            or lead.is_deleted
            or lead.isp_organization_id != isp.isp_org_id
        ):
            return False
        if lead.customer_organization_id is None:
            return isp.confined_customer_ids is None
        try:
            await IspScope.assert_customer(isp, lead.customer_organization_id)
        except Exception:  # noqa: BLE001
            return False
        return True

    async def _lead(self, isp: Any, lead_id: uuid.UUID) -> IspLead:
        lead = await self.session.get(IspLead, lead_id)
        if not await self._visible(isp, lead):
            raise IspAppsNotFoundError("Lead not found")
        return lead

    async def create(self, isp: Any, data: dict) -> dict:
        customer_id = data.pop("isp_customer_id", None)
        if customer_id is not None:
            await IspScope.assert_customer(isp, customer_id)
        elif isp.confined_customer_ids is not None:
            raise IspAppsInvalidError("Pick the customer this lead is for")
        if data.get("assignee_user_id"):
            await assert_assignee(
                isp, data["assignee_user_id"], customer_id=customer_id
            )
        lead = IspLead(
            isp_organization_id=isp.isp_org_id,
            number=await next_number(self.session, isp.isp_org_id, "lead"),
            customer_organization_id=customer_id,
            status=LeadStatus.NEW.value,
            source=data.pop("source", None) or "phone",
            **data,
        )
        self.session.add(lead)
        await self.session.flush()
        return await self.detail(isp, lead.id)

    async def update(self, isp: Any, lead_id: uuid.UUID, data: dict) -> dict:
        lead = await self._lead(isp, lead_id)
        if lead.status in TERMINAL:
            raise IspAppsInvalidError("A converted lead is read-only")
        if "isp_customer_id" in data:
            cid = data.pop("isp_customer_id")
            if cid is None and isp.confined_customer_ids is not None:
                raise IspAppsInvalidError("You cannot unlink the customer")
            if cid is not None:
                await IspScope.assert_customer(isp, cid)
            lead.customer_organization_id = cid
        if "assignee_user_id" in data and data["assignee_user_id"] is not None:
            await assert_assignee(
                isp, data["assignee_user_id"], customer_id=lead.customer_organization_id
            )
        target = data.pop("status", None)
        for k, v in data.items():
            setattr(lead, k, v)
        if target:
            check_lead_status(
                lead.status,
                target,
                dropped_reason=data.get("dropped_reason") or lead.dropped_reason,
            )
            if target != lead.status:
                from .apps2_service import lead_status_changed

                await lead_status_changed(self.session, lead, before=lead.status)
            lead.status = target
        await self.session.flush()
        return await self.detail(isp, lead.id)

    async def schedule_install(self, isp: Any, lead_id: uuid.UUID, data: dict) -> dict:
        lead = await self._lead(isp, lead_id)
        if lead.status in (
            LeadStatus.CONVERTED,
            LeadStatus.DROPPED,
            LeadStatus.NOT_FEASIBLE,
        ):
            raise IspAppsInvalidError(
                f"A {lead.status} lead cannot get an install",
                reason="ISP_STATUS_CHANGED",
            )
        task = await FieldTaskService(self.session).create(
            isp,
            {
                "isp_customer_id": lead.customer_organization_id,
                "kind": "install",
                "title": data.get("title")
                or f"Install for {lead.name} ({fmt_number('L', lead.number)})",
                "notes": data.get("notes"),
                "address": lead.address,
                "latitude": lead.latitude,
                "longitude": lead.longitude,
                "scheduled_at": data.get("scheduled_at"),
                "assignee_user_id": data.get("assignee_user_id"),
            },
            lead_id=lead.id,
        )
        lead.status = LeadStatus.INSTALL_SCHEDULED.value
        await self.session.flush()
        out = await self.detail(isp, lead.id)
        out["task"] = task
        return out

    async def convert(self, isp: Any, lead_id: uuid.UUID, data: dict) -> dict:
        lead = await self._lead(isp, lead_id)
        if lead.status in (LeadStatus.CONVERTED, LeadStatus.DROPPED):
            raise IspAppsInvalidError(
                f"A {lead.status} lead cannot be converted", reason="ISP_STATUS_CHANGED"
            )
        customer_id = data.get("isp_customer_id") or lead.customer_organization_id
        if customer_id is None:
            raise IspAppsInvalidError("Pick the customer this subscriber belongs to")
        await IspScope.assert_customer(isp, customer_id)
        if self.plans_service is None:  # pragma: no cover - wiring error
            raise IspAppsInvalidError("Subscriber creation is not available")
        first, _, last = lead.name.partition(" ")
        payload = {
            "isp_customer_id": customer_id,
            "identifier": data["identifier"],
            "package_id": data.get("package_id") or lead.interested_package_id,
            "display_name": lead.name,
            "first_name": first or None,
            "last_name": last or None,
            "phone": lead.phone,
            "email": lead.email,
            "address": lead.address,
        }
        if payload["package_id"] is None:
            raise IspAppsInvalidError("Pick the package for the new subscriber")
        sub = await self.plans_service.create_subscriber(
            isp, {k: v for k, v in payload.items() if v is not None}
        )
        lead.customer_organization_id = customer_id
        lead.converted_subscriber_id = sub.id
        lead.converted_at = _now()
        lead.status = LeadStatus.CONVERTED.value
        await self.session.flush()
        return await self.detail(isp, lead.id)

    async def list(
        self,
        isp: Any,
        *,
        status: str | None,
        isp_customer_id: uuid.UUID | None,
        assignee_user_id: uuid.UUID | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[dict], int]:
        conds = await self._scope_conds(isp, isp_customer_id)
        if conds is None:
            return [], 0
        if status:
            conds.append(IspLead.status == status)
        if assignee_user_id is not None:
            conds.append(IspLead.assignee_user_id == assignee_user_id)
        if search:
            like = f"%{search.strip()}%"
            ors = [
                IspLead.name.ilike(like),
                IspLead.phone.ilike(like),
                IspLead.city.ilike(like),
            ]
            digits = search.strip().upper().removeprefix("L-").lstrip("0")
            if digits.isdigit():
                ors.append(IspLead.number == int(digits))
            conds.append(or_(*ors))
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspLead).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspLead)
                    .where(*conds)
                    .order_by(IspLead.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.views(rows), total

    async def _scope_conds(
        self, isp: Any, isp_customer_id: uuid.UUID | None = None
    ) -> list[Any] | None:
        """Visibility for lead lists (None = the caller sees no lead)."""
        conds: list[Any] = [
            IspLead.isp_organization_id == isp.isp_org_id,
            IspLead.is_deleted.is_(False),
        ]
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            conds.append(IspLead.customer_organization_id == isp_customer_id)
            return conds
        customers = await isp.child_ids()
        if isp.confined_customer_ids is None:
            conds.append(
                or_(
                    IspLead.customer_organization_id.in_(customers),
                    IspLead.customer_organization_id.is_(None),
                )
            )
        else:
            if not customers:
                return None
            conds.append(IspLead.customer_organization_id.in_(customers))
        return conds

    async def funnel(self, isp: Any) -> dict[str, int]:
        """APPS-2: one GROUP BY (it used to load every lead to count them)."""
        out = {s.value: 0 for s in LeadStatus}
        conds = await self._scope_conds(isp)
        if conds is None:
            return out
        rows = await self.session.execute(
            select(IspLead.status, func.count()).where(*conds).group_by(IspLead.status)
        )
        for status_value, n in rows.all():
            out[status_value] = int(n)
        return out

    async def detail(self, isp: Any, lead_id: uuid.UUID) -> dict:
        lead = await self._lead(isp, lead_id)
        view = (await self.views([lead]))[0]
        tasks = (
            (
                await self.session.execute(
                    select(IspFieldTask).where(IspFieldTask.lead_id == lead.id)
                )
            )
            .scalars()
            .all()
        )
        view["tasks"] = await FieldTaskService(self.session).views(list(tasks))
        return view

    async def views(self, rows: list[Any]) -> list[dict]:
        from .apps2_service import lead_sla_views

        users = await user_names(self.session, {r.assignee_user_id for r in rows})
        orgs = await org_names(self.session, {r.customer_organization_id for r in rows})
        sla = await lead_sla_views(self.session, rows)  # APPS-2 timers
        return [
            {
                "id": r.id,
                "number": fmt_number("L", r.number),
                "name": r.name,
                "phone": r.phone,
                "email": r.email,
                "address": r.address,
                "city": r.city,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "source": r.source,
                "status": r.status,
                "isp_customer_id": r.customer_organization_id,
                "customer_name": orgs.get(r.customer_organization_id),
                "interested_package_id": r.interested_package_id,
                "assignee_user_id": r.assignee_user_id,
                "assignee_name": users.get(r.assignee_user_id),
                "feasibility_note": r.feasibility_note,
                "dropped_reason": r.dropped_reason,
                "notes": r.notes,
                "converted_subscriber_id": r.converted_subscriber_id,
                "converted_at": r.converted_at,
                "created_at": r.created_at,
                "sla": sla.get(r.id),
            }
            for r in rows
        ]

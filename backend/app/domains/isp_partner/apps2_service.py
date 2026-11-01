"""APPS-2 (ADDENDUM_06) logic on top of JAZE-5's Apps.

* Helpdesk: escalation rules ("unresolved for N minutes -> role / staff,
  plus a Telegram notice through J14 when its flag is on"), run by the
  frequent beat pass, once per (rule, ticket).
* Tasks: supervisor sign-off of completed tasks (approved, or sent back to
  the assignee for rework with a reason).
* Inventory: vendors, stock locations (warehouse / office / technician
  bag), a unit's vendor / location / TR-069 device, and an approval step
  before a unit is checked out to a customer.
* Leads: contact / conversion timers against per-ISP SLAs.

JAZE-5's services are reused unchanged where they already do the job
(``InventoryService.move_unit`` performs an approved checkout,
``assert_assignee`` vets escalation targets).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, exists, select

from .apps2_models import (
    IspAppsSettings,
    IspInventoryCheckout,
    IspInventoryUnitMeta,
    IspInventoryVendor,
    IspLeadTimer,
    IspStockLocation,
    IspTaskApproval,
    IspTicketEscalation,
    IspTicketEscalationRule,
)
from .apps_common import (
    OPEN_TICKET_STATUSES,
    IspAppsConflictError,
    IspAppsInvalidError,
    IspAppsNotFoundError,
    TaskStatus,
    UnitState,
    assert_assignee,
    fmt_number,
    org_names,
    resolve_subscriber,
    user_names,
)
from .apps_models import IspFieldTask, IspTicket, IspTicketEvent
from .constants import ISP_ROLE_SLUGS
from .scoping import IspScope

__all__ = ["Apps2Service", "lead_sla_views", "lead_status_changed", "unit_meta_views"]

logger = logging.getLogger(__name__)

LOCATION_KINDS = ("warehouse", "office", "technician_bag")
DEFAULT_LEAD_CONTACT_MINUTES = 240
DEFAULT_LEAD_CONVERT_DAYS = 14
ESCALATION_BATCH = 200


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------


async def apps_settings(session: Any, isp_org_id: uuid.UUID) -> IspAppsSettings | None:
    return (
        (
            await session.execute(
                select(IspAppsSettings).where(
                    IspAppsSettings.isp_organization_id == isp_org_id,
                    IspAppsSettings.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .first()
    )


def settings_view(st: IspAppsSettings | None) -> dict:
    return {
        "lead_contact_sla_minutes": st.lead_contact_sla_minutes
        if st
        else DEFAULT_LEAD_CONTACT_MINUTES,
        "lead_convert_sla_days": st.lead_convert_sla_days
        if st
        else DEFAULT_LEAD_CONVERT_DAYS,
    }


# ---------------------------------------------------------------------------
# leads: timers + SLA (called from LeadService)
# ---------------------------------------------------------------------------


async def _timers(
    session: Any, lead_ids: set[uuid.UUID]
) -> dict[uuid.UUID, IspLeadTimer]:
    if not lead_ids:
        return {}
    rows = (
        await session.execute(
            select(IspLeadTimer).where(
                IspLeadTimer.lead_id.in_(lead_ids), IspLeadTimer.is_deleted.is_(False)
            )
        )
    ).scalars()
    return {r.lead_id: r for r in rows}


async def lead_status_changed(session: Any, lead: Any, *, before: str) -> None:
    """Record the first contact (first move out of ``new``) and the time of
    the last status change."""
    now = _now()
    timer = (await _timers(session, {lead.id})).get(lead.id)
    if timer is None:
        timer = IspLeadTimer(lead_id=lead.id)
        session.add(timer)
    if before == "new" and timer.first_contacted_at is None:
        timer.first_contacted_at = now
    timer.status_changed_at = now


async def lead_sla_views(session: Any, leads: list[Any]) -> dict[uuid.UUID, dict]:
    """``{lead_id: {contact_due_at, first_contacted_at, contact_state,
    convert_due_at, convert_state, age_minutes}}``.

    contact_state: met | met_late | breached | pending
    convert_state: done | breached | pending
    """
    if not leads:
        return {}
    now = _now()
    timers = await _timers(session, {lead.id for lead in leads})
    per_isp: dict[uuid.UUID, dict] = {}
    out: dict[uuid.UUID, dict] = {}
    for lead in leads:
        isp_id = lead.isp_organization_id
        if isp_id not in per_isp:
            per_isp[isp_id] = settings_view(await apps_settings(session, isp_id))
        cfg = per_isp[isp_id]
        created = lead.created_at or now
        contact_due = created + timedelta(minutes=cfg["lead_contact_sla_minutes"])
        convert_due = created + timedelta(days=cfg["lead_convert_sla_days"])
        t = timers.get(lead.id)
        contacted = t.first_contacted_at if t else None
        if lead.status in ("converted", "dropped") and contacted is None:
            contacted = t.status_changed_at if t else None
        if contacted is not None:
            contact_state = "met" if contacted <= contact_due else "met_late"
        elif lead.status == "new":
            contact_state = "breached" if now > contact_due else "pending"
        else:
            # moved on before timers existed (pre-APPS-2 lead)
            contact_state = "met"
        if lead.status in ("converted", "dropped"):
            convert_state = "done"
        else:
            convert_state = "breached" if now > convert_due else "pending"
        out[lead.id] = {
            "contact_due_at": contact_due,
            "first_contacted_at": contacted,
            "contact_state": contact_state,
            "convert_due_at": convert_due,
            "convert_state": convert_state,
            "age_minutes": int((now - created).total_seconds() // 60),
        }
    return out


# ---------------------------------------------------------------------------
# inventory: unit meta (called from InventoryService.unit_views)
# ---------------------------------------------------------------------------


async def unit_meta_views(session: Any, units: list[Any]) -> dict[uuid.UUID, dict]:
    from app.domains.tr069.models import Tr069Device

    empty = {
        "vendor_id": None,
        "vendor_name": None,
        "location_id": None,
        "location_name": None,
        "location_kind": None,
        "tr069_device_id": None,
        "tr069_serial": None,
        "pending_checkout_id": None,
    }
    if not units:
        return {}
    ids = {u.id for u in units}
    metas = {
        m.unit_id: m
        for m in (
            await session.execute(
                select(IspInventoryUnitMeta).where(
                    IspInventoryUnitMeta.unit_id.in_(ids),
                    IspInventoryUnitMeta.is_deleted.is_(False),
                )
            )
        ).scalars()
    }
    pending = dict(
        (
            await session.execute(
                select(IspInventoryCheckout.unit_id, IspInventoryCheckout.id).where(
                    IspInventoryCheckout.unit_id.in_(ids),
                    IspInventoryCheckout.status == "pending",
                    IspInventoryCheckout.is_deleted.is_(False),
                )
            )
        ).all()
    )
    vendor_ids = {m.vendor_id for m in metas.values() if m.vendor_id}
    loc_ids = {m.location_id for m in metas.values() if m.location_id}
    dev_ids = {m.tr069_device_id for m in metas.values() if m.tr069_device_id}
    vendors = (
        {
            v.id: v
            for v in (
                await session.execute(
                    select(IspInventoryVendor).where(
                        IspInventoryVendor.id.in_(vendor_ids)
                    )
                )
            ).scalars()
        }
        if vendor_ids
        else {}
    )
    locs = (
        {
            loc.id: loc
            for loc in (
                await session.execute(
                    select(IspStockLocation).where(IspStockLocation.id.in_(loc_ids))
                )
            ).scalars()
        }
        if loc_ids
        else {}
    )
    devs = (
        dict(
            (
                await session.execute(
                    select(Tr069Device.id, Tr069Device.serial_number).where(
                        Tr069Device.id.in_(dev_ids)
                    )
                )
            ).all()
        )
        if dev_ids
        else {}
    )
    out: dict[uuid.UUID, dict] = {}
    for u in units:
        m = metas.get(u.id)
        row = dict(empty)
        row["pending_checkout_id"] = pending.get(u.id)
        if m is not None:
            v = vendors.get(m.vendor_id)
            loc = locs.get(m.location_id)
            row.update(
                vendor_id=m.vendor_id,
                vendor_name=v.name if v else None,
                location_id=m.location_id,
                location_name=loc.name if loc else None,
                location_kind=loc.kind if loc else None,
                tr069_device_id=m.tr069_device_id,
                tr069_serial=devs.get(m.tr069_device_id),
            )
        out[u.id] = row
    return out


# ---------------------------------------------------------------------------
# the service
# ---------------------------------------------------------------------------


class Apps2Service:
    def __init__(self, session: Any) -> None:
        self.session = session

    # -- settings --------------------------------------------------------------
    async def get_settings(self, isp: Any) -> dict:
        return settings_view(await apps_settings(self.session, isp.isp_org_id))

    async def put_settings(self, isp: Any, data: dict) -> dict:
        st = await apps_settings(self.session, isp.isp_org_id)
        if st is None:
            st = IspAppsSettings(
                isp_organization_id=isp.isp_org_id,
                lead_contact_sla_minutes=DEFAULT_LEAD_CONTACT_MINUTES,
                lead_convert_sla_days=DEFAULT_LEAD_CONVERT_DAYS,
                created_by=isp.user_id,
            )
            self.session.add(st)
        for k in ("lead_contact_sla_minutes", "lead_convert_sla_days"):
            if data.get(k) is not None:
                setattr(st, k, data[k])
        st.updated_by = isp.user_id
        await self.session.flush()
        return settings_view(st)

    # -- escalation rules ------------------------------------------------------
    async def _rule(self, isp: Any, rule_id: uuid.UUID) -> IspTicketEscalationRule:
        r = await self.session.get(IspTicketEscalationRule, rule_id)
        if r is None or r.is_deleted or r.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Escalation rule not found")
        return r

    async def _check_rule(self, isp: Any, data: dict) -> None:
        from .apps_models import IspTicketType

        role = data.get("escalate_to_role")
        if role is not None and role not in ISP_ROLE_SLUGS:
            raise IspAppsInvalidError("Pick one of the ISP staff roles")
        if data.get("escalate_to_user_id"):
            # Staff of this ISP; customer coverage is checked per ticket when
            # the rule fires (a confined technician is a valid target).
            rows = await isp.repository.isp_role_assignments(
                isp.isp_org_id, user_id=data["escalate_to_user_id"]
            )
            if not any(r.slug in ISP_ROLE_SLUGS for _a, r in rows):
                raise IspAppsInvalidError(
                    "The target is not a staff member of this ISP"
                )
        if data.get("type_id"):
            t = await self.session.get(IspTicketType, data["type_id"])
            if t is None or t.is_deleted or t.isp_organization_id != isp.isp_org_id:
                raise IspAppsNotFoundError("Ticket type not found")

    def rule_view(self, r: IspTicketEscalationRule, names: dict | None = None) -> dict:
        return {
            "id": r.id,
            "name": r.name,
            "type_id": r.type_id,
            "priority": r.priority,
            "after_minutes": r.after_minutes,
            "escalate_to_role": r.escalate_to_role,
            "escalate_to_user_id": r.escalate_to_user_id,
            "escalate_to_name": (names or {}).get(r.escalate_to_user_id),
            "notify_telegram": r.notify_telegram,
            "active": r.active,
        }

    async def list_rules(self, isp: Any) -> list[dict]:
        rows = list(
            (
                await self.session.execute(
                    select(IspTicketEscalationRule)
                    .where(
                        IspTicketEscalationRule.isp_organization_id == isp.isp_org_id,
                        IspTicketEscalationRule.is_deleted.is_(False),
                    )
                    .order_by(IspTicketEscalationRule.after_minutes)
                )
            ).scalars()
        )
        names = await user_names(self.session, {r.escalate_to_user_id for r in rows})
        return [self.rule_view(r, names) for r in rows]

    async def create_rule(self, isp: Any, data: dict) -> dict:
        if not data.get("escalate_to_role") and not data.get("escalate_to_user_id"):
            raise IspAppsInvalidError("Escalate to a role, a staff member, or both")
        await self._check_rule(isp, data)
        r = IspTicketEscalationRule(
            isp_organization_id=isp.isp_org_id,
            name=data["name"],
            type_id=data.get("type_id"),
            priority=data.get("priority"),
            after_minutes=data["after_minutes"],
            escalate_to_role=data.get("escalate_to_role"),
            escalate_to_user_id=data.get("escalate_to_user_id"),
            notify_telegram=data.get("notify_telegram", True),
            active=data.get("active", True),
            created_by=isp.user_id,
        )
        self.session.add(r)
        await self.session.flush()
        names = await user_names(self.session, {r.escalate_to_user_id})
        return self.rule_view(r, names)

    async def update_rule(self, isp: Any, rule_id: uuid.UUID, data: dict) -> dict:
        r = await self._rule(isp, rule_id)
        await self._check_rule(isp, data)
        for k, v in data.items():
            setattr(r, k, v)
        if not r.escalate_to_role and not r.escalate_to_user_id:
            raise IspAppsInvalidError("Escalate to a role, a staff member, or both")
        r.updated_by = isp.user_id
        await self.session.flush()
        names = await user_names(self.session, {r.escalate_to_user_id})
        return self.rule_view(r, names)

    async def delete_rule(self, isp: Any, rule_id: uuid.UUID) -> None:
        r = await self._rule(isp, rule_id)
        r.is_deleted, r.deleted_at = True, _now()
        await self.session.flush()

    async def list_escalations(
        self, isp: Any, *, page: int, page_size: int
    ) -> tuple[list[dict], int]:
        from sqlalchemy import func

        visible = await isp.child_ids()
        conds = [
            IspTicketEscalation.isp_organization_id == isp.isp_org_id,
            IspTicketEscalation.is_deleted.is_(False),
            IspTicket.customer_organization_id.in_(visible or [uuid.UUID(int=0)]),
        ]
        base = (
            select(IspTicketEscalation, IspTicket, IspTicketEscalationRule.name)
            .join(IspTicket, IspTicket.id == IspTicketEscalation.ticket_id)
            .join(
                IspTicketEscalationRule,
                IspTicketEscalationRule.id == IspTicketEscalation.rule_id,
            )
            .where(*conds)
        )
        total = int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(IspTicketEscalation)
                    .join(IspTicket, IspTicket.id == IspTicketEscalation.ticket_id)
                    .where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            await self.session.execute(
                base.order_by(IspTicketEscalation.escalated_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
        names = await user_names(self.session, {e.to_user_id for e, _t, _n in rows})
        orgs = await org_names(
            self.session, {t.customer_organization_id for _e, t, _n in rows}
        )
        return [
            {
                "id": e.id,
                "ticket_id": t.id,
                "ticket_number": fmt_number("T", t.number),
                "subject": t.subject,
                "customer_name": orgs.get(t.customer_organization_id),
                "ticket_status": t.status,
                "rule_id": e.rule_id,
                "rule_name": rule_name,
                "escalated_at": e.escalated_at,
                "to_role": e.to_role,
                "to_user_id": e.to_user_id,
                "to_user_name": names.get(e.to_user_id),
                "telegram_status": e.telegram_status,
                "telegram_error": e.telegram_error,
            }
            for e, t, rule_name in rows
        ], total

    async def run_escalations(
        self, isp: Any, *, now: datetime | None = None, telegram: Any = None
    ) -> int:
        """One pass for this ISP. ``telegram`` (tests) replaces the J14 send.
        Returns how many tickets were escalated."""
        now = now or _now()
        rules = list(
            (
                await self.session.execute(
                    select(IspTicketEscalationRule).where(
                        IspTicketEscalationRule.isp_organization_id == isp.isp_org_id,
                        IspTicketEscalationRule.is_deleted.is_(False),
                        IspTicketEscalationRule.active.is_(True),
                    )
                )
            ).scalars()
        )
        done = 0
        for rule in rules:
            conds = [
                IspTicket.isp_organization_id == isp.isp_org_id,
                IspTicket.is_deleted.is_(False),
                IspTicket.status.in_([s.value for s in OPEN_TICKET_STATUSES]),
                IspTicket.opened_at <= now - timedelta(minutes=rule.after_minutes),
                ~exists().where(
                    and_(
                        IspTicketEscalation.rule_id == rule.id,
                        IspTicketEscalation.ticket_id == IspTicket.id,
                    )
                ),
            ]
            if rule.type_id is not None:
                conds.append(IspTicket.type_id == rule.type_id)
            if rule.priority is not None:
                conds.append(IspTicket.priority == rule.priority)
            tickets = list(
                (
                    await self.session.execute(
                        select(IspTicket)
                        .where(*conds)
                        .order_by(IspTicket.opened_at)
                        .limit(ESCALATION_BATCH)
                    )
                ).scalars()
            )
            for t in tickets:
                await self._escalate(isp, rule, t, now=now, telegram=telegram)
                done += 1
        await self.session.flush()
        return done

    async def _escalate(
        self, isp: Any, rule: Any, t: Any, *, now: datetime, telegram: Any
    ) -> None:
        to_user = rule.escalate_to_user_id
        reassigned = False
        if to_user and to_user != t.assignee_user_id:
            try:
                await assert_assignee(
                    isp, to_user, customer_id=t.customer_organization_id
                )
                t.assignee_user_id = to_user
                reassigned = True
            except IspAppsInvalidError:
                to_user = None  # the target no longer covers this customer
        self.session.add(
            IspTicketEvent(
                ticket_id=t.id,
                kind="escalated",
                body=f"Escalated by rule '{rule.name}' after {rule.after_minutes} min",
                detail={
                    "rule_id": str(rule.id),
                    "to_role": rule.escalate_to_role,
                    "to_user_id": str(to_user) if to_user else None,
                    "reassigned": reassigned,
                },
                actor_user_id=None,
                at=now,
            )
        )
        status, error = "none", None
        if rule.notify_telegram:
            status, error = await self._telegram(isp, rule, t, telegram)
        self.session.add(
            IspTicketEscalation(
                isp_organization_id=isp.isp_org_id,
                rule_id=rule.id,
                ticket_id=t.id,
                escalated_at=now,
                to_role=rule.escalate_to_role,
                to_user_id=to_user,
                telegram_status=status,
                telegram_error=error,
            )
        )

    async def _telegram(
        self, isp: Any, rule: Any, t: Any, send: Any
    ) -> tuple[str, str | None]:
        """J14: only with ISP_TELEGRAM_ALERTS on and a bot + chat saved."""
        from .automation import _token, automation_settings, log_row, telegram_send
        from .finance_config import get_finance_settings

        if not get_finance_settings().telegram_alerts_enabled:
            return "off", None
        st = await automation_settings(self.session, isp.isp_org_id)
        token = _token(st) if st else None
        if not token or not st.telegram_chat_id:
            return "off", None
        target = " / ".join(x for x in (rule.escalate_to_role,) if x) or "staff"
        text = (
            f"Ticket {fmt_number('T', t.number)} escalated ({rule.name}): {t.subject}. "
            f"Open for more than {rule.after_minutes} min; escalated to {target}."
        )
        err = await (send or telegram_send)(token, st.telegram_chat_id, text)
        self.session.add(
            log_row(
                isp.isp_org_id,
                channel="telegram",
                trigger="ticket_escalated",  # isp_message_log.trigger is varchar(16)
                recipient_masked=f"chat …{str(st.telegram_chat_id)[-4:]}",
                summary=text,
                status="failed" if err else "sent",
                error=err,
            )
        )
        return ("failed", err[:200]) if err else ("sent", None)

    # -- task approval ---------------------------------------------------------
    async def decide_task(
        self, isp: Any, task_id: uuid.UUID, *, approve: bool, note: str | None
    ) -> dict:
        from .apps_tasks import FieldTaskService

        svc = FieldTaskService(self.session)
        t = await svc._task(isp, task_id)
        if t.status != TaskStatus.COMPLETED:
            raise IspAppsInvalidError(
                "Only a completed task can be approved or sent back"
            )
        if not approve and not (note or "").strip():
            raise IspAppsInvalidError("Say what needs redoing")
        self.session.add(
            IspTaskApproval(
                isp_organization_id=isp.isp_org_id,
                task_id=t.id,
                decision="approved" if approve else "rejected",
                note=(note or "").strip() or None,
                decided_by=isp.user_id,
                decided_at=_now(),
            )
        )
        if approve:
            t.status = TaskStatus.APPROVED.value
        else:
            # back to the assignee for rework (unclaimed if nobody holds it)
            t.status = (
                TaskStatus.ASSIGNED if t.assignee_user_id else TaskStatus.UNCLAIMED
            ).value
            t.rejected_reason = (note or "").strip()[:255]
            t.completed_at = None
        await self.session.flush()
        return (await svc.views([t]))[0]

    async def approvals_for(self, task_ids: set[uuid.UUID]) -> dict[uuid.UUID, dict]:
        if not task_ids:
            return {}
        rows = list(
            (
                await self.session.execute(
                    select(IspTaskApproval)
                    .where(
                        IspTaskApproval.task_id.in_(task_ids),
                        IspTaskApproval.is_deleted.is_(False),
                    )
                    .order_by(IspTaskApproval.decided_at)
                )
            ).scalars()
        )
        names = await user_names(self.session, {r.decided_by for r in rows})
        out: dict[uuid.UUID, dict] = {}
        for r in rows:  # latest wins
            out[r.task_id] = {
                "decision": r.decision,
                "note": r.note,
                "decided_by_name": names.get(r.decided_by),
                "decided_at": r.decided_at,
            }
        return out

    # -- vendors / locations -----------------------------------------------------
    @staticmethod
    def vendor_view(v: IspInventoryVendor) -> dict:
        return {
            k: getattr(v, k)
            for k in (
                "id",
                "name",
                "contact_name",
                "phone",
                "email",
                "gstin",
                "notes",
                "active",
            )
        }

    async def list_vendors(self, isp: Any) -> list[dict]:
        rows = (
            await self.session.execute(
                select(IspInventoryVendor)
                .where(
                    IspInventoryVendor.isp_organization_id == isp.isp_org_id,
                    IspInventoryVendor.is_deleted.is_(False),
                )
                .order_by(IspInventoryVendor.name)
            )
        ).scalars()
        return [self.vendor_view(v) for v in rows]

    async def _vendor(self, isp: Any, vendor_id: uuid.UUID) -> IspInventoryVendor:
        v = await self.session.get(IspInventoryVendor, vendor_id)
        if v is None or v.is_deleted or v.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Vendor not found")
        return v

    async def save_vendor(
        self, isp: Any, data: dict, vendor_id: uuid.UUID | None = None
    ) -> dict:
        if data.get("gstin"):
            from .gst import gstin_valid

            data["gstin"] = data["gstin"].strip().upper()
            if not gstin_valid(data["gstin"]):
                raise IspAppsInvalidError("That GSTIN fails its checksum")
        if vendor_id is None:
            v = IspInventoryVendor(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id, **data
            )
            v.active = data.get("active", True)
            self.session.add(v)
        else:
            v = await self._vendor(isp, vendor_id)
            for k, val in data.items():
                setattr(v, k, val)
            v.updated_by = isp.user_id
        await self.session.flush()
        return self.vendor_view(v)

    async def location_views(self, rows: list[IspStockLocation]) -> list[dict]:
        names = await user_names(self.session, {r.holder_user_id for r in rows})
        return [
            {
                "id": r.id,
                "name": r.name,
                "kind": r.kind,
                "holder_user_id": r.holder_user_id,
                "holder_name": names.get(r.holder_user_id),
                "address": r.address,
                "active": r.active,
            }
            for r in rows
        ]

    async def list_locations(self, isp: Any) -> list[dict]:
        rows = list(
            (
                await self.session.execute(
                    select(IspStockLocation)
                    .where(
                        IspStockLocation.isp_organization_id == isp.isp_org_id,
                        IspStockLocation.is_deleted.is_(False),
                    )
                    .order_by(IspStockLocation.kind, IspStockLocation.name)
                )
            ).scalars()
        )
        return await self.location_views(rows)

    async def _location(self, isp: Any, location_id: uuid.UUID) -> IspStockLocation:
        loc = await self.session.get(IspStockLocation, location_id)
        if loc is None or loc.is_deleted or loc.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Stock location not found")
        return loc

    async def save_location(
        self, isp: Any, data: dict, location_id: uuid.UUID | None = None
    ) -> dict:
        kind = data.get("kind")
        if kind is not None and kind not in LOCATION_KINDS:
            raise IspAppsInvalidError("Kind is warehouse, office or technician_bag")
        if data.get("holder_user_id"):
            await assert_assignee(isp, data["holder_user_id"], customer_id=None)
        if location_id is None:
            if kind == "technician_bag" and not data.get("holder_user_id"):
                raise IspAppsInvalidError(
                    "A technician bag needs the technician who carries it"
                )
            loc = IspStockLocation(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id, **data
            )
            loc.active = data.get("active", True)
            self.session.add(loc)
        else:
            loc = await self._location(isp, location_id)
            # P3-SWEEP (edit UI): an explicit null on a required column was a
            # NOT NULL 500, and an edit could leave a technician bag without
            # the technician who carries it. Both are refused as 422.
            for k in ("name", "kind", "active"):
                if k in data and data[k] is None:
                    raise IspAppsInvalidError(f"The location {k} cannot be empty")
            holder = data.get("holder_user_id", loc.holder_user_id)
            if data.get("kind", loc.kind) == "technician_bag" and not holder:
                raise IspAppsInvalidError(
                    "A technician bag needs the technician who carries it"
                )
            for k, val in data.items():
                setattr(loc, k, val)
            loc.updated_by = isp.user_id
        await self.session.flush()
        return (await self.location_views([loc]))[0]

    # -- unit meta ---------------------------------------------------------------
    async def put_unit_meta(self, isp: Any, unit_id: uuid.UUID, data: dict) -> dict:
        from app.domains.tr069.models import Tr069Device

        from .apps_inventory import InventoryService

        inv = InventoryService(self.session)
        u = await inv._unit(isp, unit_id)
        if "stock_location_id" in data:  # API name -> column name
            data["location_id"] = data.pop("stock_location_id")
        if data.get("vendor_id"):
            await self._vendor(isp, data["vendor_id"])
        if data.get("location_id"):
            await self._location(isp, data["location_id"])
        if data.get("tr069_device_id"):
            d = await self.session.get(Tr069Device, data["tr069_device_id"])
            if (
                d is None
                or getattr(d, "is_deleted", False)
                or d.isp_organization_id != isp.isp_org_id
            ):
                raise IspAppsNotFoundError("TR-069 device not found")
            if d.customer_organization_id is not None:
                # SCOPE-FIX: a confined caller may not link a device of a
                # customer outside their list (same 404 as a foreign id).
                try:
                    await IspScope.assert_customer(isp, d.customer_organization_id)
                except Exception:  # noqa: BLE001
                    raise IspAppsNotFoundError("TR-069 device not found") from None
            if (
                u.customer_organization_id is not None
                and d.customer_organization_id is not None
                and d.customer_organization_id != u.customer_organization_id
            ):
                raise IspAppsInvalidError("That device belongs to another customer")
        meta = (
            (
                await self.session.execute(
                    select(IspInventoryUnitMeta).where(
                        IspInventoryUnitMeta.unit_id == u.id,
                        IspInventoryUnitMeta.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if meta is None:
            meta = IspInventoryUnitMeta(unit_id=u.id, created_by=isp.user_id)
            self.session.add(meta)
        for k in ("vendor_id", "location_id", "tr069_device_id"):
            if k in data:
                setattr(meta, k, data[k])
        meta.updated_by = isp.user_id
        await self.session.flush()
        return (await inv.unit_views([u]))[0]

    # -- checkout approval -------------------------------------------------------
    async def checkout_views(self, rows: list[IspInventoryCheckout]) -> list[dict]:
        from .apps_models import IspInventoryUnit

        units = {
            u.id: u
            for u in (
                await self.session.execute(
                    select(IspInventoryUnit).where(
                        IspInventoryUnit.id.in_(
                            {r.unit_id for r in rows} or {uuid.UUID(int=0)}
                        )
                    )
                )
            ).scalars()
        }
        names = await user_names(
            self.session, {r.requested_by for r in rows} | {r.decided_by for r in rows}
        )
        orgs = await org_names(self.session, {r.customer_organization_id for r in rows})
        return [
            {
                "id": r.id,
                "unit_id": r.unit_id,
                "serial": units[r.unit_id].serial if r.unit_id in units else None,
                "isp_customer_id": r.customer_organization_id,
                "customer_name": orgs.get(r.customer_organization_id),
                "subscriber_id": r.subscriber_id,
                "task_id": r.task_id,
                "status": r.status,
                "note": r.note,
                "requested_by_name": names.get(r.requested_by),
                "requested_at": r.requested_at,
                "decided_by_name": names.get(r.decided_by),
                "decided_at": r.decided_at,
                "decision_note": r.decision_note,
            }
            for r in rows
        ]

    async def request_checkout(self, isp: Any, unit_id: uuid.UUID, data: dict) -> dict:
        from .apps_inventory import InventoryService, check_unit_transition

        u = await InventoryService(self.session)._unit(isp, unit_id)
        check_unit_transition(u.state, UnitState.ASSIGNED)
        customer_id = data["isp_customer_id"]
        await IspScope.assert_customer(isp, customer_id)
        if data.get("subscriber_id"):
            await resolve_subscriber(
                isp, self.session, data["subscriber_id"], customer_id=customer_id
            )
        if data.get("task_id"):
            task = await self.session.get(IspFieldTask, data["task_id"])
            if task is None or task.isp_organization_id != isp.isp_org_id:
                raise IspAppsNotFoundError("Task not found")
        open_req = (
            await self.session.execute(
                select(IspInventoryCheckout.id).where(
                    IspInventoryCheckout.unit_id == u.id,
                    IspInventoryCheckout.status == "pending",
                    IspInventoryCheckout.is_deleted.is_(False),
                )
            )
        ).first()
        if open_req is not None:
            raise IspAppsConflictError(
                "This unit already has a checkout waiting for approval"
            )
        r = IspInventoryCheckout(
            isp_organization_id=isp.isp_org_id,
            unit_id=u.id,
            customer_organization_id=customer_id,
            subscriber_id=data.get("subscriber_id"),
            task_id=data.get("task_id"),
            status="pending",
            note=data.get("note"),
            requested_by=isp.user_id,
            requested_at=_now(),
            created_by=isp.user_id,
        )
        self.session.add(r)
        await self.session.flush()
        return (await self.checkout_views([r]))[0]

    async def _checkout(self, isp: Any, checkout_id: uuid.UUID) -> IspInventoryCheckout:
        r = await self.session.get(IspInventoryCheckout, checkout_id)
        if r is None or r.is_deleted or r.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Checkout request not found")
        try:
            await IspScope.assert_customer(isp, r.customer_organization_id)
        except Exception:  # noqa: BLE001
            raise IspAppsNotFoundError("Checkout request not found") from None
        return r

    async def decide_checkout(
        self, isp: Any, checkout_id: uuid.UUID, *, approve: bool, note: str | None
    ) -> dict:
        from .apps_inventory import InventoryService

        r = await self._checkout(isp, checkout_id)
        if r.status != "pending":
            raise IspAppsInvalidError("This request was already decided")
        if approve:
            # JAZE-5's move does the checkout (transition check, customer +
            # subscriber link, movement history)
            await InventoryService(self.session).move_unit(
                isp,
                r.unit_id,
                {
                    "state": UnitState.ASSIGNED.value,
                    "isp_customer_id": r.customer_organization_id,
                    "subscriber_id": r.subscriber_id,
                    "note": note or r.note,
                },
            )
        r.status = "approved" if approve else "rejected"
        r.decided_by, r.decided_at = isp.user_id, _now()
        r.decision_note = (note or "").strip() or None
        await self.session.flush()
        return (await self.checkout_views([r]))[0]

    async def list_checkouts(self, isp: Any, *, status: str | None) -> list[dict]:
        visible = await isp.child_ids()
        conds = [
            IspInventoryCheckout.isp_organization_id == isp.isp_org_id,
            IspInventoryCheckout.is_deleted.is_(False),
            IspInventoryCheckout.customer_organization_id.in_(
                visible or [uuid.UUID(int=0)]
            ),
        ]
        if status:
            conds.append(IspInventoryCheckout.status == status)
        rows = list(
            (
                await self.session.execute(
                    select(IspInventoryCheckout)
                    .where(*conds)
                    .order_by(IspInventoryCheckout.requested_at.desc())
                    .limit(200)
                )
            ).scalars()
        )
        return await self.checkout_views(rows)

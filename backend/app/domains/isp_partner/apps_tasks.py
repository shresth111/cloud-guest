"""J16 field tasks: install / repair / survey jobs for ISP field staff.

* A task names a customer of this ISP (read through ``IspScope``), except a
  lead's survey/install before the lead has a customer: those are
  customer-less and visible to unconfined staff only.
* ``unclaimed`` tasks can be claimed by any staff member who covers the
  customer; claiming sets ``assigned``. The assignee starts, completes or
  rejects; owner/admin (``isp_apps.manage``) can reassign or cancel anything.
* A technician sees only tasks of the customers they are confined to, which
  is the general confinement rule, not a special case.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, or_, select

from .apps_common import (
    IspAppsInvalidError,
    IspAppsNotFoundError,
    TaskStatus,
    assert_assignee,
    org_names,
    resolve_subscriber,
    user_names,
)
from .apps_helpdesk import date_bounds
from .apps_models import IspFieldTask, IspTicket
from .scoping import IspScope

#: who may move a task where. "self" = only the assignee (or a manager).
TASK_TRANSITIONS: dict[str, frozenset[str]] = {
    TaskStatus.UNCLAIMED: frozenset({TaskStatus.ASSIGNED, TaskStatus.CANCELLED}),
    TaskStatus.ASSIGNED: frozenset(
        {
            TaskStatus.IN_PROGRESS,
            TaskStatus.COMPLETED,
            TaskStatus.REJECTED,
            TaskStatus.UNCLAIMED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.IN_PROGRESS: frozenset(
        {
            TaskStatus.COMPLETED,
            TaskStatus.REJECTED,
            TaskStatus.ASSIGNED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.REJECTED: frozenset(
        {TaskStatus.UNCLAIMED, TaskStatus.ASSIGNED, TaskStatus.CANCELLED}
    ),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


def _now() -> datetime:
    return datetime.now(UTC)


def check_task_transition(current: str, target: str) -> None:
    if current == target:
        return
    if target not in TASK_TRANSITIONS.get(current, frozenset()):
        raise IspAppsInvalidError(f"A {current} task cannot move to {target}")


class FieldTaskService:
    def __init__(self, session: Any) -> None:
        self.session = session

    async def _visible(self, isp: Any, t: Any) -> bool:
        if t is None or t.is_deleted or t.isp_organization_id != isp.isp_org_id:
            return False
        if t.customer_organization_id is None:
            return isp.confined_customer_ids is None
        try:
            await IspScope.assert_customer(isp, t.customer_organization_id)
        except Exception:  # noqa: BLE001
            return False
        return True

    async def _task(self, isp: Any, task_id: uuid.UUID) -> IspFieldTask:
        t = await self.session.get(IspFieldTask, task_id)
        if not await self._visible(isp, t):
            raise IspAppsNotFoundError("Task not found")
        return t

    async def create(
        self, isp: Any, data: dict, *, lead_id: uuid.UUID | None = None
    ) -> dict:
        customer_id = data.get("isp_customer_id")
        if customer_id is not None:
            await IspScope.assert_customer(isp, customer_id)
        elif isp.confined_customer_ids is not None:
            raise IspAppsInvalidError("Pick the customer this task is for")
        if data.get("subscriber_id"):
            if customer_id is None:
                raise IspAppsInvalidError("A subscriber task needs its customer")
            await resolve_subscriber(
                isp, self.session, data["subscriber_id"], customer_id=customer_id
            )
        if data.get("ticket_id"):
            ticket = await self.session.get(IspTicket, data["ticket_id"])
            if (
                ticket is None
                or ticket.isp_organization_id != isp.isp_org_id
                or ticket.customer_organization_id != customer_id
            ):
                raise IspAppsNotFoundError("Ticket not found")
        assignee = data.get("assignee_user_id")
        if assignee:
            await assert_assignee(isp, assignee, customer_id=customer_id)
        t = IspFieldTask(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=customer_id,
            subscriber_id=data.get("subscriber_id"),
            ticket_id=data.get("ticket_id"),
            lead_id=lead_id,
            kind=data.get("kind") or "install",
            title=data["title"],
            notes=data.get("notes"),
            address=data.get("address"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            scheduled_at=data.get("scheduled_at"),
            status=(TaskStatus.ASSIGNED if assignee else TaskStatus.UNCLAIMED).value,
            assignee_user_id=assignee,
        )
        self.session.add(t)
        await self.session.flush()
        return (await self.views([t]))[0]

    async def claim(self, isp: Any, task_id: uuid.UUID) -> dict:
        t = await self._task(isp, task_id)
        if t.status != TaskStatus.UNCLAIMED:
            raise IspAppsInvalidError("Only an unclaimed task can be claimed")
        await assert_assignee(isp, isp.user_id, customer_id=t.customer_organization_id)
        t.assignee_user_id = isp.user_id
        t.status = TaskStatus.ASSIGNED.value
        await self.session.flush()
        return (await self.views([t]))[0]

    async def update(
        self, isp: Any, task_id: uuid.UUID, data: dict, *, can_manage: bool
    ) -> dict:
        t = await self._task(isp, task_id)
        is_assignee = t.assignee_user_id == isp.user_id
        editable = {
            "title",
            "notes",
            "address",
            "latitude",
            "longitude",
            "scheduled_at",
            "kind",
        }
        for k in editable & data.keys():
            if not (can_manage or is_assignee):
                raise IspAppsInvalidError(
                    "Only the assignee or a manager can edit this task"
                )
            setattr(t, k, data[k])
        if (
            "assignee_user_id" in data
            and data["assignee_user_id"] != t.assignee_user_id
        ):
            if not can_manage:
                raise IspAppsInvalidError("Only a manager can reassign a task")
            new = data["assignee_user_id"]
            if new is not None:
                await assert_assignee(isp, new, customer_id=t.customer_organization_id)
            t.assignee_user_id = new
            if (
                t.status in (TaskStatus.UNCLAIMED, TaskStatus.REJECTED)
                and new is not None
            ):
                t.status = TaskStatus.ASSIGNED.value
            elif new is None and t.status in (
                TaskStatus.ASSIGNED,
                TaskStatus.IN_PROGRESS,
            ):
                t.status = TaskStatus.UNCLAIMED.value
        target = data.get("status")
        if target and target != t.status:
            check_task_transition(t.status, target)
            if target == TaskStatus.CANCELLED and not can_manage:
                raise IspAppsInvalidError("Only a manager can cancel a task")
            if target in (
                TaskStatus.IN_PROGRESS,
                TaskStatus.COMPLETED,
                TaskStatus.REJECTED,
            ) and not (is_assignee or can_manage):
                raise IspAppsInvalidError("Only the assignee can update this task")
            if target == TaskStatus.REJECTED and not data.get("rejected_reason"):
                raise IspAppsInvalidError("Say why the task is rejected")
            if (
                target in (TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS)
                and t.assignee_user_id is None
            ):
                raise IspAppsInvalidError("Assign the task first")
            now = _now()
            if target == TaskStatus.IN_PROGRESS and t.started_at is None:
                t.started_at = now
            if target == TaskStatus.COMPLETED:
                t.completed_at = now
                t.completion_note = data.get("completion_note")
            if target == TaskStatus.REJECTED:
                t.rejected_reason = data["rejected_reason"]
            if target == TaskStatus.UNCLAIMED:
                t.assignee_user_id = None
            t.status = target
        await self.session.flush()
        return (await self.views([t]))[0]

    async def list(
        self,
        isp: Any,
        *,
        isp_customer_id: uuid.UUID | None = None,
        status: str | None = None,
        kind: str | None = None,
        assignee_user_id: uuid.UUID | None = None,
        mine: bool = False,
        since: date | None = None,
        until: date | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict], int]:
        conds: list[Any] = [
            IspFieldTask.isp_organization_id == isp.isp_org_id,
            IspFieldTask.is_deleted.is_(False),
        ]
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            conds.append(IspFieldTask.customer_organization_id == isp_customer_id)
        else:
            customers = await isp.child_ids()
            if isp.confined_customer_ids is None:
                conds.append(
                    or_(
                        IspFieldTask.customer_organization_id.in_(customers),
                        IspFieldTask.customer_organization_id.is_(None),
                    )
                )
            else:
                if not customers:
                    return [], 0
                conds.append(IspFieldTask.customer_organization_id.in_(customers))
        if status:
            conds.append(IspFieldTask.status == status)
        if kind:
            conds.append(IspFieldTask.kind == kind)
        if mine:
            conds.append(IspFieldTask.assignee_user_id == isp.user_id)
        elif assignee_user_id is not None:
            conds.append(IspFieldTask.assignee_user_id == assignee_user_id)
        lo, hi = date_bounds(since, until)
        if lo:
            conds.append(IspFieldTask.scheduled_at >= lo)
        if hi:
            conds.append(IspFieldTask.scheduled_at < hi)
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspFieldTask).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspFieldTask)
                    .where(*conds)
                    .order_by(
                        IspFieldTask.scheduled_at.asc().nulls_last(),
                        IspFieldTask.created_at.desc(),
                    )
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.views(rows), total

    async def detail(self, isp: Any, task_id: uuid.UUID) -> dict:
        return (await self.views([await self._task(isp, task_id)]))[0]

    async def views(self, rows: list[Any]) -> list[dict]:
        users = await user_names(self.session, {r.assignee_user_id for r in rows})
        orgs = await org_names(self.session, {r.customer_organization_id for r in rows})
        return [
            {
                "id": r.id,
                "isp_customer_id": r.customer_organization_id,
                "customer_name": orgs.get(r.customer_organization_id),
                "subscriber_id": r.subscriber_id,
                "ticket_id": r.ticket_id,
                "lead_id": r.lead_id,
                "kind": r.kind,
                "title": r.title,
                "notes": r.notes,
                "address": r.address,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "scheduled_at": r.scheduled_at,
                "status": r.status,
                "assignee_user_id": r.assignee_user_id,
                "assignee_name": users.get(r.assignee_user_id),
                "started_at": r.started_at,
                "completed_at": r.completed_at,
                "completion_note": r.completion_note,
                "rejected_reason": r.rejected_reason,
                "created_at": r.created_at,
            }
            for r in rows
        ]

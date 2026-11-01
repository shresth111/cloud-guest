"""``/isp/apps/*``: J16 Apps (helpdesk, field tasks, announcements,
discount codes, inventory, leads).

Same guard stack as every ``/isp`` route (``isp_guards``, keys pinned at
ORGANIZATION), plus ``RequireIspAppsEnabled`` (``ISP_APPS_ENABLED``, default
OFF -> 404). Path ids are ``ticket_id``, ``type_id``, ``task_id``,
``announcement_id``, ``discount_id``, ``item_id``, ``unit_id``, ``lead_id``.
None of them is an RBAC scope alias. Query ids are ``isp_customer_id`` and
``subscriber_id``.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Query, Request, Response, UploadFile
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.notification.dependencies import get_notification_service

from .apps_announcements import AnnouncementService
from .apps_common import (
    APPS_CREATE,
    APPS_EXPORT,
    APPS_MANAGE,
    APPS_READ,
    APPS_UPDATE,
    IspAppsInvalidError,
    ItemCategory,
    LeadSource,
    LeadStatus,
    RequireIspAppsEnabled,
    RfoReason,
    TaskKind,
    TaskStatus,
    TicketPriority,
    TicketSource,
    TicketStatus,
    UnitState,
    pattern,
)
from .apps_discounts import DiscountService, evaluate_discount
from .apps_export import (
    LEAD_COLUMNS,
    MAX_EXPORT_ROWS,
    TASK_COLUMNS,
    TICKET_COLUMNS,
    UNIT_COLUMNS,
    csv_response,
    render_csv,
)
from .apps_helpdesk import HelpdeskService
from .apps_inventory import InventoryService
from .apps_leads import LeadService
from .apps_tasks import FieldTaskService
from .constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, UNCONFINABLE_ROLES
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .plans_router import get_plans_service
from .views import page as make_page

apps_router = APIRouter(
    prefix="/apps",
    tags=["ISP Partner: apps"],
    dependencies=[Depends(RequireIspAppsEnabled)],
)

_Page = Query(default=1, ge=1)
_PageSize = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
MAX_IMPORT_BYTES = 512 * 1024


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _can_manage(isp: IspContext) -> bool:
    return isp.role_slug in UNCONFINABLE_ROLES


# ============================================================================
# helpdesk
# ============================================================================
class IspAppsTicketTypeRequest(_Body):
    name: str = Field(min_length=1, max_length=100)
    sla_minutes: int | None = Field(default=None, ge=5, le=60 * 24 * 60)
    requires_rfo: bool = True
    active: bool = True
    sort_order: int = Field(default=0, ge=0, le=1000)


class IspAppsTicketTypePatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    sla_minutes: int | None = Field(default=None, ge=5, le=60 * 24 * 60)
    requires_rfo: bool | None = None
    active: bool | None = None
    sort_order: int | None = Field(default=None, ge=0, le=1000)


class IspAppsTicketCreateRequest(_Body):
    isp_customer_id: uuid.UUID
    subscriber_id: uuid.UUID | None = None
    type_id: uuid.UUID | None = None
    subject: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=20000)
    source: str = Field(default="phone", pattern=pattern(TicketSource))
    priority: str = Field(default="normal", pattern=pattern(TicketPriority))
    assignee_user_id: uuid.UUID | None = None
    close_after_raising: bool = False
    rfo_reason: str | None = Field(default=None, pattern=pattern(RfoReason))
    resolution_note: str | None = Field(default=None, max_length=5000)


class IspAppsTicketPatch(_Body):
    status: str | None = Field(default=None, pattern=pattern(TicketStatus))
    priority: str | None = Field(default=None, pattern=pattern(TicketPriority))
    type_id: uuid.UUID | None = None
    assignee_user_id: uuid.UUID | None = None
    rfo_reason: str | None = Field(default=None, pattern=pattern(RfoReason))
    resolution_note: str | None = Field(default=None, max_length=5000)


class IspAppsCommentRequest(_Body):
    body: str = Field(min_length=1, max_length=20000)


def _helpdesk(db: AsyncSession = Depends(get_db_session)) -> HelpdeskService:
    return HelpdeskService(db)


@apps_router.get("/ticket-types", dependencies=isp_guards(APPS_READ))
async def list_ticket_types(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(request, await svc.list_types(isp), "Ticket types")


@apps_router.post(
    "/ticket-types", status_code=201, dependencies=isp_guards(APPS_MANAGE)
)
async def create_ticket_type(
    request: Request,
    payload: IspAppsTicketTypeRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(
        request, await svc.create_type(isp, payload.model_dump()), "Ticket type created"
    )


@apps_router.post("/ticket-types/defaults", dependencies=isp_guards(APPS_MANAGE))
async def seed_ticket_types(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(request, await svc.seed_default_types(isp), "Standard ticket types added")


@apps_router.patch("/ticket-types/{type_id}", dependencies=isp_guards(APPS_MANAGE))
async def update_ticket_type(
    request: Request,
    type_id: uuid.UUID,
    payload: IspAppsTicketTypePatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(
        request,
        await svc.update_type(isp, type_id, payload.model_dump(exclude_unset=True)),
        "Ticket type updated",
    )


@apps_router.get("/tickets", dependencies=isp_guards(APPS_READ))
async def list_tickets(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(
        default=None, pattern="^(open|in_progress|on_hold|resolved|closed)$"
    ),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    type_id: uuid.UUID | None = Query(default=None),
    rfo_reason: str | None = Query(default=None, pattern=pattern(RfoReason)),
    sla_state: str | None = Query(default=None, pattern="^(within|breached|no_sla)$"),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    items, total = await svc.list_tickets(
        isp,
        isp_customer_id=isp_customer_id,
        subscriber_id=subscriber_id,
        status=status,
        assignee_user_id=assignee_user_id,
        type_id=type_id,
        rfo_reason=rfo_reason,
        sla=sla_state,
        since=since,
        until=until,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Tickets")


@apps_router.get("/tickets/stats", dependencies=isp_guards(APPS_READ))
async def ticket_stats(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    if since and until and until < since:
        raise IspAppsInvalidError("until is before since")
    return ok(
        request,
        await svc.stats(isp, isp_customer_id=isp_customer_id, since=since, until=until),
        "Ticket stats",
    )


@apps_router.get("/tickets/export.csv", dependencies=isp_guards(APPS_EXPORT))
async def export_tickets(
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(
        default=None, pattern="^(open|in_progress|on_hold|resolved|closed)$"
    ),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    type_id: uuid.UUID | None = Query(default=None),
    rfo_reason: str | None = Query(default=None, pattern=pattern(RfoReason)),
    sla_state: str | None = Query(default=None, pattern="^(within|breached|no_sla)$"),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> Response:
    items, _ = await svc.list_tickets(
        isp,
        isp_customer_id=isp_customer_id,
        subscriber_id=subscriber_id,
        status=status,
        assignee_user_id=assignee_user_id,
        type_id=type_id,
        rfo_reason=rfo_reason,
        sla=sla_state,
        since=since,
        until=until,
        search=search,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    return csv_response(render_csv(TICKET_COLUMNS, items), "tickets.csv")


@apps_router.post("/tickets", status_code=201, dependencies=isp_guards(APPS_CREATE))
async def create_ticket(
    request: Request,
    payload: IspAppsTicketCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(
        request, await svc.create_ticket(isp, payload.model_dump()), "Ticket raised"
    )


@apps_router.get("/tickets/{ticket_id}", dependencies=isp_guards(APPS_READ))
async def get_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(request, await svc.detail(isp, ticket_id), "Ticket")


@apps_router.patch("/tickets/{ticket_id}", dependencies=isp_guards(APPS_UPDATE))
async def update_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    payload: IspAppsTicketPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(
        request,
        await svc.update_ticket(isp, ticket_id, payload.model_dump(exclude_unset=True)),
        "Ticket updated",
    )


@apps_router.post("/tickets/{ticket_id}/comments", dependencies=isp_guards(APPS_UPDATE))
async def comment_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    payload: IspAppsCommentRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: HelpdeskService = Depends(_helpdesk),
) -> dict:
    return ok(
        request, await svc.add_comment(isp, ticket_id, payload.body), "Comment added"
    )


# ============================================================================
# field tasks
# ============================================================================
class _IspAppsGeo(_Body):
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)


class IspAppsTaskCreateRequest(_IspAppsGeo):
    isp_customer_id: uuid.UUID | None = None
    subscriber_id: uuid.UUID | None = None
    ticket_id: uuid.UUID | None = None
    kind: str = Field(default="install", pattern=pattern(TaskKind))
    title: str = Field(min_length=1, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    address: str | None = Field(default=None, max_length=1000)
    scheduled_at: datetime | None = None
    assignee_user_id: uuid.UUID | None = None


class IspAppsTaskPatch(_IspAppsGeo):
    kind: str | None = Field(default=None, pattern=pattern(TaskKind))
    title: str | None = Field(default=None, min_length=1, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    address: str | None = Field(default=None, max_length=1000)
    scheduled_at: datetime | None = None
    assignee_user_id: uuid.UUID | None = None
    status: str | None = Field(default=None, pattern=pattern(TaskStatus))
    completion_note: str | None = Field(default=None, max_length=5000)
    rejected_reason: str | None = Field(default=None, max_length=255)


def _tasks(db: AsyncSession = Depends(get_db_session)) -> FieldTaskService:
    return FieldTaskService(db)


@apps_router.get("/tasks", dependencies=isp_guards(APPS_READ))
async def list_tasks(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern=pattern(TaskStatus)),
    kind: str | None = Query(default=None, pattern=pattern(TaskKind)),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    mine: bool = Query(default=False),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: FieldTaskService = Depends(_tasks),
) -> dict:
    items, total = await svc.list(
        isp,
        isp_customer_id=isp_customer_id,
        status=status,
        kind=kind,
        assignee_user_id=assignee_user_id,
        mine=mine,
        since=since,
        until=until,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Tasks")


@apps_router.get("/tasks/export.csv", dependencies=isp_guards(APPS_EXPORT))
async def export_tasks(
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern=pattern(TaskStatus)),
    kind: str | None = Query(default=None, pattern=pattern(TaskKind)),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: FieldTaskService = Depends(_tasks),
) -> Response:
    items, _ = await svc.list(
        isp,
        isp_customer_id=isp_customer_id,
        status=status,
        kind=kind,
        assignee_user_id=assignee_user_id,
        mine=False,
        since=since,
        until=until,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    return csv_response(render_csv(TASK_COLUMNS, items), "field-tasks.csv")


@apps_router.post("/tasks", status_code=201, dependencies=isp_guards(APPS_CREATE))
async def create_task(
    request: Request,
    payload: IspAppsTaskCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: FieldTaskService = Depends(_tasks),
) -> dict:
    return ok(request, await svc.create(isp, payload.model_dump()), "Task created")


@apps_router.get("/tasks/{task_id}", dependencies=isp_guards(APPS_READ))
async def get_task(
    request: Request,
    task_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: FieldTaskService = Depends(_tasks),
) -> dict:
    return ok(request, await svc.detail(isp, task_id), "Task")


@apps_router.post("/tasks/{task_id}/claim", dependencies=isp_guards(APPS_UPDATE))
async def claim_task(
    request: Request,
    task_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: FieldTaskService = Depends(_tasks),
) -> dict:
    return ok(request, await svc.claim(isp, task_id), "Task claimed")


@apps_router.patch("/tasks/{task_id}", dependencies=isp_guards(APPS_UPDATE))
async def update_task(
    request: Request,
    task_id: uuid.UUID,
    payload: IspAppsTaskPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: FieldTaskService = Depends(_tasks),
) -> dict:
    return ok(
        request,
        await svc.update(
            isp,
            task_id,
            payload.model_dump(exclude_unset=True),
            can_manage=_can_manage(isp),
        ),
        "Task updated",
    )


# ============================================================================
# announcements
# ============================================================================
class IspAppsAnnouncementRequest(_Body):
    title: str = Field(min_length=1, max_length=150)
    body: str = Field(min_length=1, max_length=5000)
    audience: str = Field(default="all", pattern="^(all|selected)$")
    customer_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    send_email: bool = True


class IspAppsAnnouncementPatch(_Body):
    title: str | None = Field(default=None, min_length=1, max_length=150)
    body: str | None = Field(default=None, min_length=1, max_length=5000)
    audience: str | None = Field(default=None, pattern="^(all|selected)$")
    customer_ids: list[uuid.UUID] | None = Field(default=None, max_length=500)
    send_email: bool | None = None


def _announcements(
    db: AsyncSession = Depends(get_db_session),
    notifications: Any = Depends(get_notification_service),
) -> AnnouncementService:
    return AnnouncementService(db, notifications)


@apps_router.get("/announcements", dependencies=isp_guards(APPS_READ))
async def list_announcements(
    request: Request,
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: AnnouncementService = Depends(_announcements),
) -> dict:
    items, total = await svc.list(isp, page=page, page_size=page_size)
    return ok(request, make_page(items, total, page, page_size), "Announcements")


@apps_router.post(
    "/announcements", status_code=201, dependencies=isp_guards(APPS_MANAGE)
)
async def create_announcement(
    request: Request,
    payload: IspAppsAnnouncementRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: AnnouncementService = Depends(_announcements),
) -> dict:
    return ok(
        request, await svc.create(isp, payload.model_dump()), "Announcement saved"
    )


@apps_router.get("/announcements/{announcement_id}", dependencies=isp_guards(APPS_READ))
async def get_announcement(
    request: Request,
    announcement_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: AnnouncementService = Depends(_announcements),
) -> dict:
    return ok(request, await svc.detail(isp, announcement_id), "Announcement")


@apps_router.patch(
    "/announcements/{announcement_id}", dependencies=isp_guards(APPS_MANAGE)
)
async def update_announcement(
    request: Request,
    announcement_id: uuid.UUID,
    payload: IspAppsAnnouncementPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: AnnouncementService = Depends(_announcements),
) -> dict:
    return ok(
        request,
        await svc.update(isp, announcement_id, payload.model_dump(exclude_unset=True)),
        "Announcement saved",
    )


@apps_router.delete(
    "/announcements/{announcement_id}", dependencies=isp_guards(APPS_MANAGE)
)
async def delete_announcement(
    request: Request,
    announcement_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: AnnouncementService = Depends(_announcements),
) -> dict:
    await svc.delete(isp, announcement_id)
    return ok(request, None, "Announcement deleted")


@apps_router.post(
    "/announcements/{announcement_id}/send", dependencies=isp_guards(APPS_MANAGE)
)
async def send_announcement(
    request: Request,
    announcement_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: AnnouncementService = Depends(_announcements),
) -> dict:
    return ok(request, await svc.send(isp, announcement_id), "Announcement sent")


# ============================================================================
# discount codes
# ============================================================================
class _IspAppsDiscountFields(_Body):
    description: str | None = Field(default=None, max_length=200)
    max_discount_paise: int | None = Field(default=None, gt=0)
    min_amount_paise: int | None = Field(default=None, ge=0)
    max_uses: int | None = Field(default=None, ge=1)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    package_ids: list[uuid.UUID] | None = Field(default=None, max_length=200)
    active: bool = True


class IspAppsDiscountRequest(_IspAppsDiscountFields):
    code: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    kind: str = Field(pattern="^(percent|flat)$")
    value: int = Field(gt=0)

    @model_validator(mode="after")
    def _check(self) -> IspAppsDiscountRequest:
        if self.kind == "percent" and self.value > 10000:
            raise ValueError("a percent discount is at most 100% (10000 basis points)")
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class IspAppsDiscountPatch(_Body):
    description: str | None = Field(default=None, max_length=200)
    max_discount_paise: int | None = Field(default=None, gt=0)
    min_amount_paise: int | None = Field(default=None, ge=0)
    max_uses: int | None = Field(default=None, ge=1)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    package_ids: list[uuid.UUID] | None = Field(default=None, max_length=200)
    active: bool | None = None


class IspAppsDiscountPreviewRequest(_Body):
    code: str = Field(min_length=1, max_length=32)
    gross_paise: int = Field(gt=0)
    package_id: uuid.UUID | None = None


def _discounts(db: AsyncSession = Depends(get_db_session)) -> DiscountService:
    return DiscountService(db)


@apps_router.get("/discounts", dependencies=isp_guards(APPS_READ))
async def list_discounts(
    request: Request,
    active: bool | None = Query(default=None),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: DiscountService = Depends(_discounts),
) -> dict:
    items, total = await svc.list(isp, active=active, page=page, page_size=page_size)
    return ok(request, make_page(items, total, page, page_size), "Discounts")


@apps_router.post("/discounts", status_code=201, dependencies=isp_guards(APPS_MANAGE))
async def create_discount(
    request: Request,
    payload: IspAppsDiscountRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: DiscountService = Depends(_discounts),
) -> dict:
    return ok(request, await svc.create(isp, payload.model_dump()), "Discount created")


@apps_router.post("/discounts/preview", dependencies=isp_guards(APPS_READ))
async def preview_discount(
    request: Request,
    payload: IspAppsDiscountPreviewRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    q = await evaluate_discount(
        db,
        isp.isp_org_id,
        payload.code,
        gross_paise=payload.gross_paise,
        package_id=payload.package_id,
    )
    return ok(
        request,
        {
            "discount_id": q.discount_id,
            "code": q.code,
            "label": q.label,
            "gross_paise": payload.gross_paise,
            "discount_paise": q.amount_paise,
            "taxable_paise": payload.gross_paise - q.amount_paise,
        },
        "Discount applies",
    )


@apps_router.patch("/discounts/{discount_id}", dependencies=isp_guards(APPS_MANAGE))
async def update_discount(
    request: Request,
    discount_id: uuid.UUID,
    payload: IspAppsDiscountPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: DiscountService = Depends(_discounts),
) -> dict:
    return ok(
        request,
        await svc.update(isp, discount_id, payload.model_dump(exclude_unset=True)),
        "Discount updated",
    )


@apps_router.get(
    "/discounts/{discount_id}/redemptions", dependencies=isp_guards(APPS_READ)
)
async def discount_redemptions(
    request: Request,
    discount_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: DiscountService = Depends(_discounts),
) -> dict:
    return ok(request, await svc.redemptions(isp, discount_id), "Redemptions")


# ============================================================================
# inventory
# ============================================================================
class IspAppsItemRequest(_Body):
    name: str = Field(min_length=1, max_length=120)
    sku: str = Field(min_length=1, max_length=40)
    category: str = Field(pattern=pattern(ItemCategory))
    notes: str | None = Field(default=None, max_length=2000)


class IspAppsItemPatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    sku: str | None = Field(default=None, min_length=1, max_length=40)
    category: str | None = Field(default=None, pattern=pattern(ItemCategory))
    notes: str | None = Field(default=None, max_length=2000)


class IspAppsUnitRequest(_Body):
    item_id: uuid.UUID
    serial: str = Field(min_length=1, max_length=64)
    mac: str | None = Field(default=None, max_length=17)
    note: str | None = Field(default=None, max_length=2000)


class IspAppsUnitMoveRequest(_Body):
    state: str = Field(pattern=pattern(UnitState))
    isp_customer_id: uuid.UUID | None = None
    subscriber_id: uuid.UUID | None = None
    note: str | None = Field(default=None, max_length=2000)


def _inventory(db: AsyncSession = Depends(get_db_session)) -> InventoryService:
    return InventoryService(db)


@apps_router.get("/inventory/items", dependencies=isp_guards(APPS_READ))
async def list_items(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    return ok(request, await svc.list_items(isp), "Items")


@apps_router.post(
    "/inventory/items", status_code=201, dependencies=isp_guards(APPS_MANAGE)
)
async def create_item(
    request: Request,
    payload: IspAppsItemRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    return ok(request, await svc.create_item(isp, payload.model_dump()), "Item created")


@apps_router.patch("/inventory/items/{item_id}", dependencies=isp_guards(APPS_MANAGE))
async def update_item(
    request: Request,
    item_id: uuid.UUID,
    payload: IspAppsItemPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    return ok(
        request,
        await svc.update_item(isp, item_id, payload.model_dump(exclude_unset=True)),
        "Item updated",
    )


@apps_router.get("/inventory/units", dependencies=isp_guards(APPS_READ))
async def list_units(
    request: Request,
    item_id: uuid.UUID | None = Query(default=None),
    state: str | None = Query(default=None, pattern=pattern(UnitState)),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=64),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    items, total = await svc.list_units(
        isp,
        item_id=item_id,
        state=state,
        isp_customer_id=isp_customer_id,
        subscriber_id=subscriber_id,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Units")


@apps_router.get("/inventory/units/export.csv", dependencies=isp_guards(APPS_EXPORT))
async def export_units(
    item_id: uuid.UUID | None = Query(default=None),
    state: str | None = Query(default=None, pattern=pattern(UnitState)),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=64),
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> Response:
    items, _ = await svc.list_units(
        isp,
        item_id=item_id,
        state=state,
        isp_customer_id=isp_customer_id,
        subscriber_id=subscriber_id,
        search=search,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    return csv_response(render_csv(UNIT_COLUMNS, items), "inventory-units.csv")


@apps_router.post(
    "/inventory/units", status_code=201, dependencies=isp_guards(APPS_CREATE)
)
async def add_unit(
    request: Request,
    payload: IspAppsUnitRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    return ok(request, await svc.add_unit(isp, payload.model_dump()), "Unit added")


@apps_router.post("/inventory/units/import", dependencies=isp_guards(APPS_CREATE))
async def import_units(
    request: Request,
    file: UploadFile = File(...),
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    raw = await file.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        raise IspAppsInvalidError("The CSV is larger than 512 KB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise IspAppsInvalidError("The CSV must be UTF-8") from None
    return ok(request, await svc.import_csv(isp, text), "Import finished")


@apps_router.get("/inventory/units/{unit_id}", dependencies=isp_guards(APPS_READ))
async def get_unit(
    request: Request,
    unit_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    return ok(request, await svc.unit_detail(isp, unit_id), "Unit")


@apps_router.post(
    "/inventory/units/{unit_id}/move", dependencies=isp_guards(APPS_UPDATE)
)
async def move_unit(
    request: Request,
    unit_id: uuid.UUID,
    payload: IspAppsUnitMoveRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: InventoryService = Depends(_inventory),
) -> dict:
    return ok(
        request, await svc.move_unit(isp, unit_id, payload.model_dump()), "Unit updated"
    )


# ============================================================================
# leads
# ============================================================================
class IspAppsLeadRequest(_IspAppsGeo):
    name: str = Field(min_length=1, max_length=200)
    phone: str | None = Field(default=None, max_length=20)
    email: str | None = Field(default=None, max_length=255)
    address: str | None = Field(default=None, max_length=1000)
    city: str | None = Field(default=None, max_length=100)
    source: str = Field(default="phone", pattern=pattern(LeadSource))
    isp_customer_id: uuid.UUID | None = None
    interested_package_id: uuid.UUID | None = None
    assignee_user_id: uuid.UUID | None = None
    notes: str | None = Field(default=None, max_length=5000)


class IspAppsLeadPatch(_IspAppsGeo):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    phone: str | None = Field(default=None, max_length=20)
    email: str | None = Field(default=None, max_length=255)
    address: str | None = Field(default=None, max_length=1000)
    city: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, pattern=pattern(LeadSource))
    status: str | None = Field(default=None, pattern=pattern(LeadStatus))
    isp_customer_id: uuid.UUID | None = None
    interested_package_id: uuid.UUID | None = None
    assignee_user_id: uuid.UUID | None = None
    feasibility_note: str | None = Field(default=None, max_length=5000)
    dropped_reason: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=5000)


class IspAppsLeadInstallRequest(_Body):
    title: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    scheduled_at: datetime | None = None
    assignee_user_id: uuid.UUID | None = None


class IspAppsLeadConvertRequest(_Body):
    identifier: str = Field(min_length=3, max_length=255)
    package_id: uuid.UUID | None = None
    isp_customer_id: uuid.UUID | None = None


def _leads(
    db: AsyncSession = Depends(get_db_session),
    plans: Any = Depends(get_plans_service),
) -> LeadService:
    return LeadService(db, plans)


@apps_router.get("/leads", dependencies=isp_guards(APPS_READ))
async def list_leads(
    request: Request,
    status: str | None = Query(default=None, pattern=pattern(LeadStatus)),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    items, total = await svc.list(
        isp,
        status=status,
        isp_customer_id=isp_customer_id,
        assignee_user_id=assignee_user_id,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Leads")


@apps_router.get("/leads/export.csv", dependencies=isp_guards(APPS_EXPORT))
async def export_leads(
    status: str | None = Query(default=None, pattern=pattern(LeadStatus)),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> Response:
    items, _ = await svc.list(
        isp,
        status=status,
        isp_customer_id=isp_customer_id,
        assignee_user_id=assignee_user_id,
        search=search,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    return csv_response(render_csv(LEAD_COLUMNS, items), "leads.csv")


@apps_router.get("/leads/funnel", dependencies=isp_guards(APPS_READ))
async def lead_funnel(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    return ok(request, await svc.funnel(isp), "Lead funnel")


@apps_router.post("/leads", status_code=201, dependencies=isp_guards(APPS_CREATE))
async def create_lead(
    request: Request,
    payload: IspAppsLeadRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    return ok(request, await svc.create(isp, payload.model_dump()), "Lead added")


@apps_router.get("/leads/{lead_id}", dependencies=isp_guards(APPS_READ))
async def get_lead(
    request: Request,
    lead_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    return ok(request, await svc.detail(isp, lead_id), "Lead")


@apps_router.patch("/leads/{lead_id}", dependencies=isp_guards(APPS_UPDATE))
async def update_lead(
    request: Request,
    lead_id: uuid.UUID,
    payload: IspAppsLeadPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    return ok(
        request,
        await svc.update(isp, lead_id, payload.model_dump(exclude_unset=True)),
        "Lead updated",
    )


@apps_router.post("/leads/{lead_id}/install", dependencies=isp_guards(APPS_CREATE))
async def schedule_lead_install(
    request: Request,
    lead_id: uuid.UUID,
    payload: IspAppsLeadInstallRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    return ok(
        request,
        await svc.schedule_install(isp, lead_id, payload.model_dump()),
        "Install scheduled",
    )


@apps_router.post(
    "/leads/{lead_id}/convert",
    dependencies=isp_guards(APPS_MANAGE),
)
async def convert_lead(
    request: Request,
    lead_id: uuid.UUID,
    payload: IspAppsLeadConvertRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: LeadService = Depends(_leads),
) -> dict:
    return ok(
        request, await svc.convert(isp, lead_id, payload.model_dump()), "Lead converted"
    )


__all__ = ["apps_router"]

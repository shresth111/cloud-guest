"""Batch B5 (ADDENDUM_04 §3): Alerts, Support Tickets, Staff Activity.

Three different shapes, on purpose:

1. **Alerts on a venue** are TWINS (``MONITOR_TWINS``, registered in
   ``twins_all``) -- but only of the list / get / acknowledge / resolve
   routes, whose tenant check was fixed (PR #98). The by-id alert RULE routes
   (``/alerts/rules/{rule_id}``) still carry the known path-id defect and are
   NOT twinned. The venue's rules come from a NEW read here,
   ``GET /isp/venue/alert-rules``, over ``alert_rules WHERE organization_id =
   <the customer>``.

   ``GET /isp/alerts`` is the ISP-wide feed: alerts whose ``organization_id``
   is one of the caller's (confinement-aware) customers. An empty customer
   list is an empty feed, never "every org".

2. **Support Tickets** go ISP -> Wyfy. The ISP is the requester, so these are
   wrappers that call the original ticket handlers with
   ``requesting_organization_id = <the ISP org>``. Tickets therefore appear in
   Master's existing tickets page under the ISP org. A ticket about one
   customer names it in the description (resolved through ``IspScope``, so it
   is always one of the caller's customers).

3. **Staff Activity** is a new read over ``audit_log_entries``: rows whose
   actor is one of this ISP's staff, OR whose organization is the ISP org or
   one of its customers. Filterable by staff member, customer and action.
   ``isp_partner.assign`` (owner/admin).

Every route here has the four ISP guards pinned at ORGANIZATION and resolves
targets through ``IspScope``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.models import AuthUser, User
from app.domains.monitoring import router as monitoring_routes
from app.domains.monitoring.constants import AlertStatus
from app.domains.monitoring.dependencies import get_alert_service
from app.domains.monitoring.models import Alert, AlertRule
from app.domains.organization.models import Organization
from app.domains.rbac.dependencies import CurrentUser
from app.domains.rbac.models import AuditLogEntry
from app.domains.support_tickets import router as ticket_routes
from app.domains.support_tickets.dependencies import get_ticket_service
from app.domains.support_tickets.schemas import (
    TicketCreateRequest,
    TicketReplyCreateRequest,
)

from .constants import (
    ISP_MONITOR_READ,
    ISP_MONITOR_UPDATE,
    ISP_PARTNER_ASSIGN,
    ISP_SUPPORT_CREATE,
    ISP_SUPPORT_READ,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .scoping import IspScope
from .twins import Extra, Param, TwinSpec
from .venue_headers import resolve_venue_location

__all__ = ["MONITOR_TWINS", "monitor_support_router"]

_AlertId = Param("alert_id", "path", uuid.UUID)

MONITOR_TWINS: tuple[TwinSpec, ...] = (
    # The customer's alerts. ``list_alerts`` filters by organization (and
    # optionally router), not by location; the router extra is pinned to the
    # header location, so the partner page filters to this venue's routers.
    TwinSpec(
        method="GET",
        path="/venue/alerts",
        permission_key=ISP_MONITOR_READ,
        handler=monitoring_routes.list_alerts,
        target="header_location",
        params=(
            Param("alert_status", "query", AlertStatus | None, None),
            Param("severity", "query", str | None, None),
            Param("page", "query", int, 1),
            Param("page_size", "query", int, 25),
        ),
        extras=(Extra("isp_router_id", "query", "router", "router_id"),),
        deps={"service": get_alert_service},
        inject={"organization_id": ("org",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/alerts/{alert_id}",
        permission_key=ISP_MONITOR_READ,
        handler=monitoring_routes.get_alert,
        target="header_location",
        params=(_AlertId,),
        deps={"service": get_alert_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/alerts/{alert_id}/acknowledge",
        permission_key=ISP_MONITOR_UPDATE,
        handler=monitoring_routes.acknowledge_alert,
        target="header_location",
        params=(_AlertId,),
        paid_write=False,  # monitoring_router is not on _PAID_WRITES
        deps={"service": get_alert_service},
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/alerts/{alert_id}/resolve",
        permission_key=ISP_MONITOR_UPDATE,
        handler=monitoring_routes.resolve_alert,
        target="header_location",
        params=(_AlertId,),
        paid_write=False,  # monitoring_router is not on _PAID_WRITES
        deps={"service": get_alert_service},
        inject={"requesting_organization_id": ("org",)},
    ),
)

monitor_support_router = APIRouter(tags=["ISP Partner: monitoring & support"])


def _page(page: int, page_size: int, total: int) -> dict[str, Any]:
    pages = (total + page_size - 1) // page_size if total else 0
    return {
        "page": page,
        "page_size": page_size,
        "total_items": total,
        "total_pages": pages,
        "has_next": page < pages,
        "has_previous": page > 1,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# ============================================================================
# Alerts: the venue's rules (new read) and the ISP-wide feed
# ============================================================================


@monitor_support_router.get(
    "/venue/alert-rules", dependencies=isp_guards(ISP_MONITOR_READ)
)
async def list_venue_alert_rules(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    """The customer's alert rules, read-only. Not the original by-id handler
    (path-id defect); a plain query pinned to the resolved customer org."""
    location = await resolve_venue_location(request, isp)
    org_id = location.organization_id
    where = and_(AlertRule.organization_id == org_id, AlertRule.is_deleted.is_(False))
    total = (
        await db.execute(select(func.count()).select_from(AlertRule).where(where))
    ).scalar_one()
    rows = (
        await db.execute(
            select(AlertRule)
            .where(where)
            .order_by(AlertRule.created_at.desc(), AlertRule.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars()
    items = [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "trigger_type": r.trigger_type,
            "target_component": r.target_component,
            "severity": r.severity,
            "is_active": r.is_active,
            "created_at": _iso(r.created_at),
        }
        for r in rows
    ]
    return ok(request, {"items": items, **_page(page, page_size, total)})


@monitor_support_router.get("/alerts", dependencies=isp_guards(ISP_MONITOR_READ))
async def list_isp_alerts(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(None),
    alert_status: AlertStatus | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    """Alerts across my customers (confinement-aware)."""
    customer_id, _, _ = await IspScope.optional_filters(
        isp, isp_customer_id=isp_customer_id
    )
    org_ids = [customer_id] if customer_id is not None else await isp.child_ids()
    if not org_ids:
        return ok(request, {"items": [], **_page(page, page_size, 0)})
    conditions: list[Any] = [Alert.organization_id.in_(org_ids)]
    if hasattr(Alert, "is_deleted"):
        conditions.append(Alert.is_deleted.is_(False))
    if alert_status is not None:
        conditions.append(Alert.status == alert_status.value)
    total = (
        await db.execute(select(func.count()).select_from(Alert).where(*conditions))
    ).scalar_one()
    rows = (
        await db.execute(
            select(Alert, Organization.name)
            .join(Organization, Organization.id == Alert.organization_id)
            .where(*conditions)
            .order_by(Alert.triggered_at.desc(), Alert.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    items = [
        {
            "id": str(a.id),
            "isp_customer_id": str(a.organization_id),
            "customer_name": name,
            "isp_location_id": str(a.location_id) if a.location_id else None,
            "isp_router_id": str(a.router_id) if a.router_id else None,
            "status": a.status,
            "severity": a.severity,
            "message": a.message,
            "triggered_at": _iso(a.triggered_at),
            "acknowledged_at": _iso(a.acknowledged_at),
            "resolved_at": _iso(a.resolved_at),
        }
        for a, name in rows
    ]
    return ok(request, {"items": items, **_page(page, page_size, total)})


# ============================================================================
# Support Tickets: ISP -> Wyfy (the ISP org is the requester)
# ============================================================================


class IspTicketCreateRequest(BaseModel):
    subject: str = Field(..., min_length=2, max_length=255)
    description: str = Field(..., min_length=5)
    category: str | None = None
    priority: str = "medium"
    #: Optional: which of my customers this is about. Checked via IspScope.
    isp_customer_id: uuid.UUID | None = None


@monitor_support_router.get(
    "/support-tickets", dependencies=isp_guards(ISP_SUPPORT_READ)
)
async def list_isp_tickets(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    ticket_status: str | None = Query(None),
    priority: str | None = Query(None),
    search: str | None = Query(None),
    isp: IspContext = Depends(RequireIspPartner),
    service=Depends(get_ticket_service),
):
    return await ticket_routes.list_tickets(
        request,
        page=page,
        page_size=page_size,
        ticket_status=ticket_status,
        priority=priority,
        search=search,
        requesting_organization_id=isp.isp_org_id,
        service=service,
    )


@monitor_support_router.post(
    "/support-tickets",
    status_code=201,
    dependencies=isp_guards(ISP_SUPPORT_CREATE),
)
async def create_isp_ticket(
    request: Request,
    payload: IspTicketCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    user: AuthUser = Depends(CurrentUser),
    service=Depends(get_ticket_service),
):
    description = payload.description
    if payload.isp_customer_id is not None:
        customer = await IspScope.assert_customer(isp, payload.isp_customer_id)
        description = (
            f"{description}\n\n-- ISP customer: {customer.name} ({customer.id})"
        )
    original = TicketCreateRequest(
        location_id=None,
        subject=payload.subject,
        description=description,
        category=payload.category,
        priority=payload.priority,
    )
    return await ticket_routes.create_ticket(
        request,
        payload=original,
        user=user,
        requesting_organization_id=isp.isp_org_id,
        service=service,
    )


@monitor_support_router.get(
    "/support-tickets/{ticket_id}", dependencies=isp_guards(ISP_SUPPORT_READ)
)
async def get_isp_ticket(
    request: Request,
    ticket_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service=Depends(get_ticket_service),
):
    return await ticket_routes.get_ticket(
        request,
        ticket_id=ticket_id,
        requesting_organization_id=isp.isp_org_id,
        service=service,
    )


@monitor_support_router.get(
    "/support-tickets/{ticket_id}/replies", dependencies=isp_guards(ISP_SUPPORT_READ)
)
async def list_isp_ticket_replies(
    request: Request,
    ticket_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service=Depends(get_ticket_service),
):
    return await ticket_routes.list_ticket_replies(
        request,
        ticket_id=ticket_id,
        requesting_organization_id=isp.isp_org_id,
        service=service,
    )


@monitor_support_router.post(
    "/support-tickets/{ticket_id}/replies",
    status_code=201,
    dependencies=isp_guards(ISP_SUPPORT_CREATE),
)
async def create_isp_ticket_reply(
    request: Request,
    ticket_id: uuid.UUID,
    payload: TicketReplyCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    user: AuthUser = Depends(CurrentUser),
    service=Depends(get_ticket_service),
):
    return await ticket_routes.create_ticket_reply(
        request,
        ticket_id=ticket_id,
        payload=payload,
        user=user,
        requesting_organization_id=isp.isp_org_id,
        service=service,
    )


# ============================================================================
# Staff Activity: what this ISP's staff did, across its customers
# ============================================================================


@monitor_support_router.get(
    "/staff-activity", dependencies=isp_guards(ISP_PARTNER_ASSIGN)
)
async def list_staff_activity(
    request: Request,
    isp_user_id: uuid.UUID | None = Query(None),
    isp_customer_id: uuid.UUID | None = Query(None),
    action: str | None = Query(None, max_length=50),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    staff_ids = sorted(
        {
            a.user_id
            for a, _ in await isp.repository.isp_role_assignments(isp.isp_org_id)
        }
    )
    child_ids = await isp.child_ids()
    scope_orgs = [isp.isp_org_id, *child_ids]

    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
        scope = AuditLogEntry.organization_id == isp_customer_id
    else:
        scope = or_(
            AuditLogEntry.actor_user_id.in_(staff_ids) if staff_ids else false(),
            AuditLogEntry.organization_id.in_(scope_orgs),
        )
    conditions: list[Any] = [scope]
    if isp_user_id is not None:
        if isp_user_id not in staff_ids:
            return ok(request, {"items": [], **_page(page, page_size, 0)})
        conditions.append(AuditLogEntry.actor_user_id == isp_user_id)
    if action:
        conditions.append(AuditLogEntry.action == action)
    if since is not None:
        conditions.append(AuditLogEntry.created_at >= since)
    if until is not None:
        conditions.append(AuditLogEntry.created_at < until)

    total = (
        await db.execute(
            select(func.count()).select_from(AuditLogEntry).where(*conditions)
        )
    ).scalar_one()
    rows = (
        await db.execute(
            select(AuditLogEntry, User.first_name, User.last_name, User.email)
            .outerjoin(User, User.id == AuditLogEntry.actor_user_id)
            .where(*conditions)
            .order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    names = dict(
        (
            await db.execute(
                select(Organization.id, Organization.name).where(
                    Organization.id.in_(scope_orgs)
                )
            )
        ).all()
    )
    staff = set(staff_ids)
    items = [
        {
            "id": str(e.id),
            "created_at": _iso(e.created_at),
            "action": e.action,
            "entity_type": e.entity_type,
            "description": e.description,
            "actor": (
                {
                    "isp_user_id": str(e.actor_user_id),
                    "name": f"{first or ''} {last or ''}".strip() or email,
                    "is_isp_staff": e.actor_user_id in staff,
                }
                if e.actor_user_id
                else None
            ),
            "isp_customer_id": (
                str(e.organization_id)
                if e.organization_id and e.organization_id != isp.isp_org_id
                else None
            ),
            "customer_name": (
                names.get(e.organization_id)
                if e.organization_id and e.organization_id != isp.isp_org_id
                else None
            ),
        }
        for e, first, last, email in rows
    ]
    return ok(request, {"items": items, **_page(page, page_size, total)})

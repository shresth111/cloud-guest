"""``/isp/apps/*`` APPS-2 routes (ADDENDUM_06), behind ``ISP_APPS_ENABLED``
like the rest of Apps. Existing ``isp_apps.*`` keys only:

* read lists -> ``isp_apps.read``
* request a checkout, set a unit's vendor / location / device -> ``isp_apps.update``
* settings, escalation rules, vendors, locations, approve / send back a
  task, approve / reject a checkout -> ``isp_apps.manage``

Paths avoid JAZE-5's ``/tickets/{ticket_id}``-style captures
(``/escalation-rules``, not ``/tickets/escalation-rules``).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .apps2_service import LOCATION_KINDS, Apps2Service
from .apps_common import (
    APPS_MANAGE,
    APPS_READ,
    APPS_UPDATE,
    RequireIspAppsEnabled,
    TicketPriority,
    pattern,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .views import page as make_page

__all__ = ["apps2_router"]

apps2_router = APIRouter(
    prefix="/apps",
    tags=["ISP Partner: Apps (APPS-2)"],
    dependencies=[Depends(RequireIspAppsEnabled)],
)


def _svc(db: AsyncSession = Depends(get_db_session)) -> Apps2Service:
    return Apps2Service(db)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SettingsBody(_Body):
    lead_contact_sla_minutes: int | None = Field(default=None, ge=5, le=60 * 24 * 30)
    lead_convert_sla_days: int | None = Field(default=None, ge=1, le=365)


class RuleBody(_Body):
    name: str = Field(min_length=1, max_length=100)
    type_id: uuid.UUID | None = None
    priority: str | None = Field(default=None, pattern=pattern(TicketPriority))
    after_minutes: int = Field(ge=5, le=60 * 24 * 60)
    escalate_to_role: str | None = Field(default=None, max_length=40)
    escalate_to_user_id: uuid.UUID | None = None
    notify_telegram: bool = True
    active: bool = True


class RulePatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    type_id: uuid.UUID | None = None
    priority: str | None = Field(default=None, pattern=pattern(TicketPriority))
    after_minutes: int | None = Field(default=None, ge=5, le=60 * 24 * 60)
    escalate_to_role: str | None = Field(default=None, max_length=40)
    escalate_to_user_id: uuid.UUID | None = None
    notify_telegram: bool | None = None
    active: bool | None = None


class DecisionBody(_Body):
    note: str | None = Field(default=None, max_length=2000)


class VendorBody(_Body):
    name: str = Field(min_length=1, max_length=120)
    contact_name: str | None = Field(default=None, max_length=120)
    phone: str | None = Field(default=None, max_length=20)
    email: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, min_length=15, max_length=15)
    notes: str | None = Field(default=None, max_length=2000)
    active: bool = True


class VendorPatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    contact_name: str | None = Field(default=None, max_length=120)
    phone: str | None = Field(default=None, max_length=20)
    email: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, min_length=15, max_length=15)
    notes: str | None = Field(default=None, max_length=2000)
    active: bool | None = None


_KIND = "^(" + "|".join(LOCATION_KINDS) + ")$"


class LocationBody(_Body):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(pattern=_KIND)
    holder_user_id: uuid.UUID | None = None
    address: str | None = Field(default=None, max_length=1000)
    active: bool = True


class LocationPatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    kind: str | None = Field(default=None, pattern=_KIND)
    holder_user_id: uuid.UUID | None = None
    address: str | None = Field(default=None, max_length=1000)
    active: bool | None = None


class UnitMetaBody(_Body):
    vendor_id: uuid.UUID | None = None
    stock_location_id: uuid.UUID | None = None
    tr069_device_id: uuid.UUID | None = None


class CheckoutBody(_Body):
    isp_customer_id: uuid.UUID
    subscriber_id: uuid.UUID | None = None
    task_id: uuid.UUID | None = None
    note: str | None = Field(default=None, max_length=2000)


# -- settings ---------------------------------------------------------------------


@apps2_router.get("/settings", dependencies=isp_guards(APPS_READ))
async def get_apps_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.get_settings(isp), "Apps settings")


@apps2_router.put("/settings", dependencies=isp_guards(APPS_MANAGE))
async def put_apps_settings(
    request: Request,
    payload: SettingsBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.put_settings(isp, payload.model_dump(exclude_unset=True)),
        "Saved",
    )


# -- helpdesk escalation ----------------------------------------------------------


@apps2_router.get("/escalation-rules", dependencies=isp_guards(APPS_READ))
async def list_escalation_rules(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.list_rules(isp), "Escalation rules")


@apps2_router.post(
    "/escalation-rules", status_code=201, dependencies=isp_guards(APPS_MANAGE)
)
async def create_escalation_rule(
    request: Request,
    payload: RuleBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.create_rule(isp, payload.model_dump()), "Rule added")


@apps2_router.patch("/escalation-rules/{rule_id}", dependencies=isp_guards(APPS_MANAGE))
async def update_escalation_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: RulePatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.update_rule(isp, rule_id, payload.model_dump(exclude_unset=True)),
        "Rule saved",
    )


@apps2_router.delete(
    "/escalation-rules/{rule_id}", dependencies=isp_guards(APPS_MANAGE)
)
async def delete_escalation_rule(
    request: Request,
    rule_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    await svc.delete_rule(isp, rule_id)
    return ok(request, None, "Rule deleted")


@apps2_router.get("/escalations", dependencies=isp_guards(APPS_READ))
async def list_escalations(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    items, total = await svc.list_escalations(isp, page=page, page_size=page_size)
    return ok(request, make_page(items, total, page, page_size), "Escalations")


# -- task approval ------------------------------------------------------------------


@apps2_router.post("/tasks/{task_id}/approve", dependencies=isp_guards(APPS_MANAGE))
async def approve_task(
    request: Request,
    task_id: uuid.UUID,
    payload: DecisionBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.decide_task(isp, task_id, approve=True, note=payload.note),
        "Approved",
    )


@apps2_router.post("/tasks/{task_id}/send-back", dependencies=isp_guards(APPS_MANAGE))
async def send_back_task(
    request: Request,
    task_id: uuid.UUID,
    payload: DecisionBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.decide_task(isp, task_id, approve=False, note=payload.note),
        "Sent back for rework",
    )


# -- vendors / stock locations ---------------------------------------------------------


@apps2_router.get("/inventory/vendors", dependencies=isp_guards(APPS_READ))
async def list_vendors(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.list_vendors(isp), "Vendors")


@apps2_router.post(
    "/inventory/vendors", status_code=201, dependencies=isp_guards(APPS_MANAGE)
)
async def create_vendor(
    request: Request,
    payload: VendorBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.save_vendor(isp, payload.model_dump()), "Vendor added")


@apps2_router.patch(
    "/inventory/vendors/{vendor_id}", dependencies=isp_guards(APPS_MANAGE)
)
async def update_vendor(
    request: Request,
    vendor_id: uuid.UUID,
    payload: VendorPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.save_vendor(isp, payload.model_dump(exclude_unset=True), vendor_id),
        "Vendor saved",
    )


@apps2_router.get("/inventory/locations", dependencies=isp_guards(APPS_READ))
async def list_locations(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.list_locations(isp), "Stock locations")


@apps2_router.post(
    "/inventory/locations", status_code=201, dependencies=isp_guards(APPS_MANAGE)
)
async def create_location(
    request: Request,
    payload: LocationBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request, await svc.save_location(isp, payload.model_dump()), "Location added"
    )


@apps2_router.patch(
    "/inventory/locations/{stock_location_id}", dependencies=isp_guards(APPS_MANAGE)
)
async def update_location(
    request: Request,
    stock_location_id: uuid.UUID,
    payload: LocationPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.save_location(
            isp, payload.model_dump(exclude_unset=True), stock_location_id
        ),
        "Location saved",
    )


# -- unit meta + checkout approval -----------------------------------------------


@apps2_router.put(
    "/inventory/units/{unit_id}/meta", dependencies=isp_guards(APPS_UPDATE)
)
async def put_unit_meta(
    request: Request,
    unit_id: uuid.UUID,
    payload: UnitMetaBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.put_unit_meta(isp, unit_id, payload.model_dump(exclude_unset=True)),
        "Unit saved",
    )


@apps2_router.post(
    "/inventory/units/{unit_id}/checkout",
    status_code=201,
    dependencies=isp_guards(APPS_UPDATE),
)
async def request_checkout(
    request: Request,
    unit_id: uuid.UUID,
    payload: CheckoutBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(
        request,
        await svc.request_checkout(isp, unit_id, payload.model_dump()),
        "Checkout requested",
    )


@apps2_router.get("/inventory/checkouts", dependencies=isp_guards(APPS_READ))
async def list_checkouts(
    request: Request,
    status: str | None = Query(
        default=None, pattern="^(pending|approved|rejected|cancelled)$"
    ),
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    return ok(request, await svc.list_checkouts(isp, status=status), "Checkouts")


@apps2_router.post(
    "/inventory/checkouts/{checkout_id}/approve", dependencies=isp_guards(APPS_MANAGE)
)
async def approve_checkout(
    request: Request,
    checkout_id: uuid.UUID,
    payload: DecisionBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    out: Any = await svc.decide_checkout(
        isp, checkout_id, approve=True, note=payload.note
    )
    return ok(request, out, "Checkout approved")


@apps2_router.post(
    "/inventory/checkouts/{checkout_id}/reject", dependencies=isp_guards(APPS_MANAGE)
)
async def reject_checkout(
    request: Request,
    checkout_id: uuid.UUID,
    payload: DecisionBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: Apps2Service = Depends(_svc),
) -> dict:
    out: Any = await svc.decide_checkout(
        isp, checkout_id, approve=False, note=payload.note
    )
    return ok(request, out, "Checkout rejected")

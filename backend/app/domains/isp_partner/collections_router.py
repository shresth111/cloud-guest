"""COLLECTIONS-1 routes (``/isp/collections``), behind
``ISP_COLLECTIONS_ENABLED`` (default OFF: every route is a 404).

* overdue list ranked by risk band and amount, with the reasons of the score
* promise-to-pay (date + note), kept/broken from real payments; a missed
  promise gets a follow-up task in the daily pass
* collection notes + one timeline (notes, promises, bills, payments, reminders)
* cash in the field through the existing payment code, with an 80/58 mm slip
* end-of-day cash handover per collector, approved by owner/admin
* "predicted collections this week"

Keys (seeded by the isp_partner seeder): ``isp_collections.read`` /
``.update`` (notes, promises) / ``.collect`` (cash, own handover) /
``.approve`` (owner/admin).
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .collections_config import (
    ISP_COLLECTIONS_APPROVE,
    ISP_COLLECTIONS_COLLECT,
    ISP_COLLECTIONS_READ,
    ISP_COLLECTIONS_UPDATE,
    RequireCollectionsEnabled,
)
from .collections_logic import NOTE_OUTCOMES
from .collections_service import IspCollectionsService
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok

collections_router = APIRouter(prefix="/collections", tags=["ISP Partner: collections"])
_ON = [Depends(RequireCollectionsEnabled)]


def get_collections_service(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspCollectionsService:
    return IspCollectionsService(session=db, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CollPartyBody(_Body):
    subscriber_id: uuid.UUID | None = None
    isp_customer_id: uuid.UUID | None = None


class CollNoteRequest(CollPartyBody):
    body: str = Field(min_length=1, max_length=2000)
    outcome: str | None = Field(
        default=None, pattern="^(" + "|".join(NOTE_OUTCOMES) + ")$"
    )


class CollPromiseRequest(CollPartyBody):
    promised_on: date
    amount_paise: int | None = Field(default=None, gt=0, le=10_000_000_00)
    note: str | None = Field(default=None, max_length=1000)


class CollReasonRequest(_Body):
    reason: str = Field(min_length=1, max_length=255)


class CollCashRequest(CollPartyBody):
    invoice_id: uuid.UUID | None = None
    amount_paise: int = Field(gt=0, le=10_000_000_00)
    note: str | None = Field(default=None, max_length=1000)


class CollHandoverRequest(_Body):
    business_date: date
    declared_paise: int = Field(ge=0, le=10_000_000_00)
    note: str | None = Field(default=None, max_length=1000)


class CollDecisionRequest(_Body):
    received_paise: int | None = Field(default=None, ge=0, le=10_000_000_00)
    note: str | None = Field(default=None, max_length=1000)


_Page = Query(default=1, ge=1)
_PageSize = Query(default=50, ge=1, le=200)


# --------------------------------------------------------------------------
# overdue list + forecast
# --------------------------------------------------------------------------


@collections_router.get("/overdue", dependencies=_ON + isp_guards(ISP_COLLECTIONS_READ))
async def overdue(
    request: Request,
    party_kind: Literal["subscriber", "customer"] | None = None,
    isp_customer_id: uuid.UUID | None = None,
    band: Literal["high", "medium", "low"] | None = None,
    promise: Literal["open", "broken", "none"] | None = None,
    min_days: int = Query(default=0, ge=0, le=3650),
    search: str | None = Query(default=None, max_length=100),
    sort: Literal["priority", "amount", "age", "score"] = "priority",
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    data = await svc.overdue(
        isp,
        party_kind=party_kind,
        isp_customer_id=isp_customer_id,
        band=band,
        promise=promise,
        min_days=min_days,
        search=search,
        sort=sort,
        page=page,
        page_size=page_size,
    )
    return ok(request, data, "Overdue")


@collections_router.get(
    "/forecast", dependencies=_ON + isp_guards(ISP_COLLECTIONS_READ)
)
async def forecast(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    return ok(request, await svc.forecast(isp), "Predicted collections this week")


# --------------------------------------------------------------------------
# timeline, notes, promises
# --------------------------------------------------------------------------


@collections_router.get(
    "/subscribers/{subscriber_id}/timeline",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_READ),
)
async def subscriber_timeline(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    party, _ = await svc.resolve_party(
        isp, subscriber_id=subscriber_id, isp_customer_id=None
    )
    return ok(request, await svc.timeline(isp, party), "Collections timeline")


@collections_router.get(
    "/customers/{isp_customer_id}/timeline",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_READ),
)
async def customer_timeline(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    party, _ = await svc.resolve_party(
        isp, subscriber_id=None, isp_customer_id=isp_customer_id
    )
    return ok(request, await svc.timeline(isp, party), "Collections timeline")


@collections_router.post(
    "/notes", status_code=201, dependencies=_ON + isp_guards(ISP_COLLECTIONS_UPDATE)
)
async def add_note(
    request: Request,
    body: CollNoteRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    party, _ = await svc.resolve_party(
        isp, subscriber_id=body.subscriber_id, isp_customer_id=body.isp_customer_id
    )
    view = await svc.add_note(isp, party, body=body.body, outcome=body.outcome)
    await svc.session.commit()
    return ok(request, view, "Note added")


@collections_router.get(
    "/promises", dependencies=_ON + isp_guards(ISP_COLLECTIONS_READ)
)
async def list_promises(
    request: Request,
    status: Literal["open", "kept", "broken", "cancelled", "superseded"] | None = None,
    due: Literal["today", "week", "missed"] | None = None,
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    data = await svc.list_promises(
        isp, status=status, due=due, page=page, page_size=page_size
    )
    return ok(request, data, "Promises")


@collections_router.post(
    "/promises", status_code=201, dependencies=_ON + isp_guards(ISP_COLLECTIONS_UPDATE)
)
async def create_promise(
    request: Request,
    body: CollPromiseRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    party, _ = await svc.resolve_party(
        isp, subscriber_id=body.subscriber_id, isp_customer_id=body.isp_customer_id
    )
    view = await svc.create_promise(
        isp,
        party,
        promised_on=body.promised_on,
        amount_paise=body.amount_paise,
        note=body.note,
    )
    await svc.session.commit()
    return ok(request, view, "Promise recorded")


@collections_router.post(
    "/promises/{promise_id}/cancel",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_UPDATE),
)
async def cancel_promise(
    request: Request,
    promise_id: uuid.UUID,
    body: CollReasonRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    view = await svc.cancel_promise(isp, promise_id, reason=body.reason)
    await svc.session.commit()
    return ok(request, view, "Promise cancelled")


# --------------------------------------------------------------------------
# cash in the field
# --------------------------------------------------------------------------


@collections_router.post(
    "/cash", status_code=201, dependencies=_ON + isp_guards(ISP_COLLECTIONS_COLLECT)
)
async def collect_cash(
    request: Request,
    body: CollCashRequest,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", max_length=100
    ),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    party, _ = await svc.resolve_party(
        isp, subscriber_id=body.subscriber_id, isp_customer_id=body.isp_customer_id
    )
    view = await svc.collect_cash(
        isp,
        party,
        amount_paise=body.amount_paise,
        invoice_id=body.invoice_id,
        note=body.note,
        idempotency_key=idempotency_key,
    )
    await svc.session.commit()
    return ok(request, view, "Cash recorded")


@collections_router.get(
    "/payments/{payment_id}/slip.pdf",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_COLLECT),
)
async def cash_slip(
    payment_id: uuid.UUID,
    width: int = Query(default=80, description="58 or 80 (mm)"),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> Response:
    from .thermal_pdf import render_thermal_receipt

    if width not in (58, 80):
        from .exceptions import IspBadRequestError

        raise IspBadRequestError(
            "Slip width is 58 or 80 mm", field="width", reason="ISP_QUERY_INVALID"
        )
    pay = await svc.slip_payment(isp, payment_id)
    view = (await svc.billing.payment_rows(isp, [pay]))[0]
    seller = svc.billing.settings_view(await svc.billing.settings(isp)) or {}
    name = view.get("customer_name") or ""
    if pay.subscriber_id is not None:
        from .apps_common import subscriber_label
        from .plans_models import IspSubscriber

        s = await svc.session.get(IspSubscriber, pay.subscriber_id)
        if s is not None:
            name = subscriber_label(s)
    pdf = render_thermal_receipt(
        view,
        seller=seller,
        isp_name=isp.organization.name,
        customer_name=name,
        width_mm=width,
    )
    filename = view["receipt_number"].replace("/", "-") + f"-{width}mm.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


@collections_router.get(
    "/cash/mine", dependencies=_ON + isp_guards(ISP_COLLECTIONS_COLLECT)
)
async def my_cash(
    request: Request,
    day: date | None = Query(default=None, alias="date"),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    return ok(request, await svc.my_cash(isp, day or svc.today(isp)), "My cash")


# --------------------------------------------------------------------------
# handovers
# --------------------------------------------------------------------------


@collections_router.post(
    "/handovers",
    status_code=201,
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_COLLECT),
)
async def submit_handover(
    request: Request,
    body: CollHandoverRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    view = await svc.submit_handover(
        isp,
        business_date=body.business_date,
        declared_paise=body.declared_paise,
        note=body.note,
    )
    await svc.session.commit()
    return ok(request, view, "Handover submitted")


@collections_router.get(
    "/handovers", dependencies=_ON + isp_guards(ISP_COLLECTIONS_COLLECT)
)
async def list_handovers(
    request: Request,
    status: Literal["submitted", "approved", "rejected"] | None = None,
    isp_user_id: uuid.UUID | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    data = await svc.list_handovers(
        isp,
        status=status,
        isp_user_id=isp_user_id,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
    )
    return ok(request, data, "Handovers")


@collections_router.get(
    "/handovers/{handover_id}",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_COLLECT),
)
async def handover_detail(
    request: Request,
    handover_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    return ok(request, await svc.handover_detail(isp, handover_id), "Handover")


@collections_router.post(
    "/handovers/{handover_id}/approve",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_APPROVE),
)
async def approve_handover(
    request: Request,
    handover_id: uuid.UUID,
    body: CollDecisionRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    view = await svc.decide_handover(
        isp,
        handover_id,
        approve=True,
        received_paise=body.received_paise,
        note=body.note,
    )
    await svc.session.commit()
    return ok(request, view, "Handover approved")


@collections_router.post(
    "/handovers/{handover_id}/reject",
    dependencies=_ON + isp_guards(ISP_COLLECTIONS_APPROVE),
)
async def reject_handover(
    request: Request,
    handover_id: uuid.UUID,
    body: CollDecisionRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCollectionsService = Depends(get_collections_service),
) -> dict:
    view = await svc.decide_handover(
        isp, handover_id, approve=False, received_paise=None, note=body.note
    )
    await svc.session.commit()
    return ok(request, view, "Handover rejected")


__all__ = ["collections_router"]

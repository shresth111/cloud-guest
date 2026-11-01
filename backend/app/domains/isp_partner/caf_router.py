"""``/isp/caf/*``: CAF-2 workbench (behind ``ISP_CAF_WORKBENCH_ENABLED``,
default OFF -> 404 everywhere).

Keys (existing ones only, same split as JAZE-3's KYC routes):

* read / search / prefill -> ``isp_partner.read``
* extras, CAF number -> ``isp_partner.update``
* PDF, ZIP export -> ``isp_partner.export`` (both audited)
* signatory + stamp -> ``isp_partner.manage``
* lead source additionally needs ``ISP_APPS_ENABLED`` and ``isp_apps.read``;
  converting a lead needs ``isp_apps.manage`` (JAZE-5's own rule).

Path ids: ``subscriber_id`` and ``lead_id``; neither is a scope alias.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator, get_rbac_repository
from app.domains.rbac.exceptions import PermissionDeniedError

from .apps_common import APPS_MANAGE, APPS_READ, get_isp_apps_settings
from .caf_models import APPLICANT_CATEGORIES
from .caf_service import EXPORT_MAX, IspCafService, RequireIspCafEnabled
from .compliance_logic import ID_TYPES
from .constants import (
    ISP_PARTNER_MANAGE,
    ISP_PARTNER_READ,
    ISP_PARTNER_UPDATE,
    ISP_SUBSCRIBERS_KYC,  # RBAC-FIX
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError, IspError
from .http import ok
from .plans_router import get_plans_service
from .plans_service import IspPlansService

__all__ = ["caf_router"]

caf_router = APIRouter(
    prefix="/caf",
    tags=["ISP Partner: CAF workbench"],
    dependencies=[Depends(RequireIspCafEnabled)],
)


class IspCafLeadsOffError(IspError):
    code = "ISP_CAF_LEADS_OFF"
    status_code_default = 404
    default_message = "Leads are not switched on"


def _svc(
    db: AsyncSession = Depends(get_db_session),
    audit=Depends(get_rbac_repository),  # noqa: B008
) -> IspCafService:
    return IspCafService(db, audit)


async def _need(isp: IspContext, av: AccessValidator, key: str) -> None:
    from .router import effective_isp_permissions

    if key not in await effective_isp_permissions(isp, av):
        raise PermissionDeniedError(key, "organization")


async def _leads_on(isp: IspContext, av: AccessValidator, key: str = APPS_READ) -> None:
    if not get_isp_apps_settings().enabled:
        raise IspCafLeadsOffError()
    await _need(isp, av, key)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ExtrasBody(_Body):
    applicant_category: str | None = Field(
        default=None, pattern="^(" + "|".join(APPLICANT_CATEGORIES) + ")$"
    )
    applicant_category_other: str | None = Field(default=None, max_length=60)
    father_or_spouse_name: str | None = Field(default=None, max_length=200)
    plot_no: str | None = Field(default=None, max_length=60)
    locality: str | None = Field(default=None, max_length=120)
    district: str | None = Field(default=None, max_length=100)


class NumberBody(_Body):
    mode: str = Field(pattern="^(auto|custom)$")
    number: str | None = Field(default=None, max_length=40)


class ConvertBody(_Body):
    identifier: str | None = Field(default=None, min_length=3, max_length=255)
    package_id: uuid.UUID | None = None
    isp_customer_id: uuid.UUID | None = None


class ProfileBody(_Body):
    signatory_name: str | None = Field(default=None, max_length=120)
    signatory_designation: str | None = Field(default=None, max_length=120)


class ExportBody(_Body):
    subscriber_ids: list[uuid.UUID] = Field(default_factory=list, max_length=EXPORT_MAX)
    since: date | None = None
    until: date | None = None


def _pdf(content: bytes, name: str, media: str = "application/pdf") -> Response:
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


# -- options + search ----------------------------------------------------------


@caf_router.get("/options", dependencies=isp_guards(ISP_PARTNER_READ))
async def caf_options(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    from .router import effective_isp_permissions

    held = set(await effective_isp_permissions(isp, av))
    return ok(
        request,
        {
            "leads": get_isp_apps_settings().enabled and APPS_READ in held,
            "convert_leads": get_isp_apps_settings().enabled and APPS_MANAGE in held,
            "applicant_categories": list(APPLICANT_CATEGORIES),
            "id_types": list(ID_TYPES),
            "export_max": EXPORT_MAX,
            "profile": await svc.profile_view(isp),
        },
        "CAF options",
    )


@caf_router.get("/search", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC))
async def caf_search(
    request: Request,
    q: str = Query(min_length=2, max_length=100),
    source: str = Query(default="subscriber", pattern="^(subscriber|lead)$"),
    limit: int = Query(default=10, ge=1, le=25),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
    plans: IspPlansService = Depends(get_plans_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    """Zone-scoped: both sources read through ``isp.child_ids()`` /
    the caller's confinement."""
    if source == "lead":
        from .apps_leads import LeadService

        await _leads_on(isp, av)
        rows, _ = await LeadService(svc.session).list(
            isp,
            status=None,
            isp_customer_id=None,
            assignee_user_id=None,
            search=q,
            page=1,
            page_size=limit,
        )
        hits: list[dict[str, Any]] = [
            {
                "source": "lead",
                "id": str(r["id"]),
                "label": r["name"],
                "detail": " · ".join(
                    x
                    for x in (r["number"], r.get("phone"), r.get("customer_name"))
                    if x
                ),
                "status": r["status"],
                "converted_subscriber_id": str(r["converted_subscriber_id"])
                if r.get("converted_subscriber_id")
                else None,
                "caf_number": None,
            }
            for r in rows
        ]
    else:
        from .subscriber360_service import IspSubscriber360Service

        rows = await IspSubscriber360Service(plans=plans, guest_service=None).typeahead(
            isp, q, limit
        )
        nums = await svc.caf_numbers([uuid.UUID(r["id"]) for r in rows])
        hits = [
            {
                "source": "subscriber",
                "id": r["id"],
                "label": r["name"] or r["identifier"],
                "detail": " · ".join(
                    str(x)
                    for x in (
                        f"#{r['circuit_id']}",
                        r["identifier"],
                        r.get("customer_name"),
                    )
                    if x
                ),
                "status": r["status"],
                "converted_subscriber_id": None,
                "caf_number": nums.get(uuid.UUID(r["id"])),
            }
            for r in rows
        ]
    return ok(request, hits, "Matches")


# -- subscriber -----------------------------------------------------------------


@caf_router.get(
    "/subscribers/{subscriber_id}", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC)
)
async def caf_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> dict:
    return ok(request, await svc.prefill_subscriber(isp, subscriber_id), "CAF")


@caf_router.put(
    "/subscribers/{subscriber_id}/extras", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def caf_subscriber_extras(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: ExtrasBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> dict:
    out = await svc.put_extras(
        isp, subscriber_id=subscriber_id, data=payload.model_dump(exclude_unset=True)
    )
    await svc.session.commit()
    return ok(request, out, "Saved")


@caf_router.post(
    "/subscribers/{subscriber_id}/number", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def caf_subscriber_number(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: NumberBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> dict:
    if payload.mode == "custom" and not payload.number:
        raise IspBadRequestError("Give the CAF number", field="number")
    out = await svc.assign_number(
        isp, subscriber_id, custom=payload.number if payload.mode == "custom" else None
    )
    await svc.session.commit()
    return ok(request, out, "CAF number assigned")


@caf_router.get(
    "/subscribers/{subscriber_id}/caf.pdf", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC)
)
async def caf_subscriber_pdf(
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> Response:
    s = await svc.subscriber(isp, subscriber_id)
    content, name = await svc.pdf_for(isp, s)
    await svc.session.commit()
    return _pdf(content, name)


# -- lead -------------------------------------------------------------------------


@caf_router.get("/leads/{lead_id}", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC))
async def caf_lead(
    request: Request,
    lead_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    await _leads_on(isp, av)
    return ok(request, await svc.prefill_lead(isp, lead_id), "CAF")


@caf_router.put("/leads/{lead_id}/extras", dependencies=isp_guards(ISP_PARTNER_UPDATE))
async def caf_lead_extras(
    request: Request,
    lead_id: uuid.UUID,
    payload: ExtrasBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    await _leads_on(isp, av)
    out = await svc.put_extras(
        isp, lead_id=lead_id, data=payload.model_dump(exclude_unset=True)
    )
    await svc.session.commit()
    return ok(request, out, "Saved")


@caf_router.post(
    "/leads/{lead_id}/convert", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def caf_lead_convert(
    request: Request,
    lead_id: uuid.UUID,
    payload: ConvertBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
    plans: IspPlansService = Depends(get_plans_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    """The lead's name, phone, email and address carry over (JAZE-5); only a
    login id (default: the lead's phone) and a package are needed, and only
    when the lead does not already say."""
    await _leads_on(isp, av, APPS_MANAGE)
    out = await svc.convert_lead(isp, lead_id, plans, payload.model_dump())
    await svc.session.commit()
    return ok(request, out, "Converted")


# -- bulk export ----------------------------------------------------------------


@caf_router.post("/export", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC))
async def caf_export(
    payload: ExportBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> Response:
    content, _, _ = await svc.export_zip(
        isp,
        subscriber_ids=payload.subscriber_ids or None,
        since=payload.since,
        until=payload.until,
    )
    await svc.session.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return _pdf(content, f"caf-export-{stamp}.zip", "application/zip")


# -- ISP profile: signatory + stamp ----------------------------------------------


@caf_router.put("/profile", dependencies=isp_guards(ISP_PARTNER_MANAGE))
async def caf_profile(
    request: Request,
    payload: ProfileBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> dict:
    out = await svc.put_profile(isp, payload.model_dump(exclude_unset=True))
    await svc.session.commit()
    return ok(request, out, "Saved")


@caf_router.post("/profile/stamp", dependencies=isp_guards(ISP_PARTNER_MANAGE))
async def caf_stamp_upload(
    request: Request,
    file: UploadFile = File(...),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> dict:
    content = await file.read(8 * 1024 * 1024 + 1)
    out = await svc.set_stamp(isp, content)
    await svc.session.commit()
    return ok(request, out, "Stamp saved")


@caf_router.delete("/profile/stamp", dependencies=isp_guards(ISP_PARTNER_MANAGE))
async def caf_stamp_delete(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspCafService = Depends(_svc),
) -> dict:
    out = await svc.set_stamp(isp, None)
    await svc.session.commit()
    return ok(request, out, "Stamp removed")

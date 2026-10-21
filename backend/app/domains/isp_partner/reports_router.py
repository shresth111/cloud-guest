"""``/isp/reports/*`` (API_CONTRACT §4.10)."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .constants import AUDIT_ISP_REPORT_EXPORTED, ISP_PARTNER_EXPORT, ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError
from .http import ok
from .reports import SECTIONS, IspReportsService, render_csv, render_pdf

reports_router = APIRouter(prefix="/reports", tags=["ISP Partner: reports"])


def get_reports_service(isp: IspContext = Depends(RequireIspPartner)) -> IspReportsService:
    return IspReportsService(isp.repository)


@reports_router.get("/summary", dependencies=isp_guards(ISP_PARTNER_READ))
async def report_summary(
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspReportsService = Depends(get_reports_service),
) -> dict:
    from app.domains.tr069.sync import sync_on_read

    await sync_on_read(isp)
    data = await service.summary(
        isp, since=since, until=until, isp_customer_id=isp_customer_id
    )
    return ok(request, data, "ISP report")


@reports_router.get("/export", dependencies=isp_guards(ISP_PARTNER_EXPORT))
async def report_export(
    format: str = Query(pattern="^(csv|pdf)$"),
    section: str = Query(default="all", pattern="^(portfolio|guest_activity|usage_by_customer|tr069|all)$"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspReportsService = Depends(get_reports_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    """CSV: one section per file (``section=all`` is PDF only, else 422).
    PDF: every section through ``analytics.export.render_report``."""
    if format == "csv" and section == "all":
        raise IspBadRequestError("CSV exports one section at a time", field="section")
    report = await service.summary(
        isp, since=since, until=until, isp_customer_id=isp_customer_id
    )
    first = report["since"][:10].replace("-", "")
    last = report["until"][:10].replace("-", "")
    slug = isp.organization.slug
    if format == "csv":
        content = render_csv(section, report)
        media = "text/csv; charset=utf-8"
        name = f"isp-report-{slug}-{first}-{last}.csv"
    else:
        content = render_pdf(report, title=f"{isp.organization.name}: ISP report")
        media = "application/pdf"
        name = f"isp-report-{slug}-{first}-{last}.pdf"
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action=AUDIT_ISP_REPORT_EXPORTED,
        entity_type="organization",
        entity_id=isp.isp_org_id,
        description=f"ISP report exported ({format}, {section})",
        event_metadata={
            "console": "isp",
            "format": format,
            "section": section,
            "sections": list(SECTIONS) if section == "all" else [section],
            "isp_customer_id": str(isp_customer_id) if isp_customer_id else None,
        },
        organization_id=isp.isp_org_id,
        location_id=None,
    )
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )

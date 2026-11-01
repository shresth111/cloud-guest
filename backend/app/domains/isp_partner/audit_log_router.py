"""AUDIT-LOG route (``/isp/audit-log``), behind ``ISP_AUDIT_LOG_ENABLED``
(default OFF). Owner/admin only: ``isp_audit.read`` / ``isp_audit.export``
are seeded for isp-owner and isp-admin and nobody else."""

from __future__ import annotations

import uuid
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .audit_log_config import ISP_AUDIT_EXPORT, ISP_AUDIT_READ, RequireAuditLogEnabled
from .audit_log_service import IspAuditLogService
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok

audit_log_router = APIRouter(prefix="/audit-log", tags=["ISP Partner: audit log"])
_ON = [Depends(RequireAuditLogEnabled)]
Source = Literal["all", "actions", "sign_ins"]


def get_audit_log_service(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspAuditLogService:
    return IspAuditLogService(session=db, audit=audit)


def _filters(
    source: Source = "all",
    isp_user_id: uuid.UUID | None = None,
    isp_customer_id: uuid.UUID | None = None,
    action: str | None = Query(default=None, max_length=50),
    entity_type: str | None = Query(default=None, max_length=50),
    search: str | None = Query(default=None, max_length=100),
    since: date | None = None,
    until: date | None = None,
) -> dict:
    return {
        "source": source,
        "isp_user_id": isp_user_id,
        "isp_customer_id": isp_customer_id,
        "action": action,
        "entity_type": entity_type,
        "search": search,
        "since": since,
        "until": until,
    }


@audit_log_router.get("", dependencies=_ON + isp_guards(ISP_AUDIT_READ))
async def audit_log(
    request: Request,
    f: dict = Depends(_filters),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspAuditLogService = Depends(get_audit_log_service),
) -> dict:
    return ok(
        request, await svc.page(isp, page=page, page_size=page_size, **f), "Audit log"
    )


@audit_log_router.get("/facets", dependencies=_ON + isp_guards(ISP_AUDIT_READ))
async def facets(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspAuditLogService = Depends(get_audit_log_service),
) -> dict:
    return ok(request, await svc.facets(isp), "Audit log filters")


@audit_log_router.get("/export.csv", dependencies=_ON + isp_guards(ISP_AUDIT_EXPORT))
async def export_csv(
    f: dict = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspAuditLogService = Depends(get_audit_log_service),
) -> Response:
    content, n = await svc.csv(isp, **f)
    await svc.session.commit()
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="isp-audit-log.csv"',
            "X-Row-Count": str(n),
        },
    )


__all__ = ["audit_log_router"]

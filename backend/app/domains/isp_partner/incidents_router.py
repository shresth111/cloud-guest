"""INCIDENTS-1 routes (``/isp/incidents``), behind ``ISP_INCIDENTS_ENABLED``
(default OFF: every route is a 404).

Keys (isp_partner seeder): ``isp_incidents.read`` / ``.manage`` (open, status,
notes, refresh) / ``.execute`` (broadcast; grace also needs
``isp_subscribers.update``) / ``.export`` (affected CSV).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .incidents_config import (
    ISP_INCIDENTS_EXECUTE,
    ISP_INCIDENTS_EXPORT,
    ISP_INCIDENTS_MANAGE,
    ISP_INCIDENTS_READ,
    RequireIncidentsEnabled,
)
from .incidents_service import IspIncidentsService

incidents_router = APIRouter(prefix="/incidents", tags=["ISP Partner: incidents"])
_ON = [Depends(RequireIncidentsEnabled)]

ScopeKind = Literal["router", "fiber_node", "zone"]
RfoReason = Literal["fiber_cut", "power_olt", "cpe_fault", "upstream", "other"]


def get_incidents_service(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspIncidentsService:
    return IspIncidentsService(session=db, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IncCreateRequest(_Body):
    scope_kind: ScopeKind
    isp_router_id: uuid.UUID | None = None
    fiber_node_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    title: str | None = Field(default=None, min_length=1, max_length=200)
    severity: Literal["minor", "major", "critical"] = "major"
    started_at: datetime | None = None
    note: str | None = Field(default=None, max_length=2000)


class IncStatusRequest(_Body):
    status: Literal["identified", "resolved"]
    note: str | None = Field(default=None, max_length=2000)
    rfo_reason: RfoReason | None = None
    rfo_note: str | None = Field(default=None, max_length=2000)
    resolved_at: datetime | None = None


class IncNoteRequest(_Body):
    body: str = Field(min_length=1, max_length=2000)


class IncGraceRequest(_Body):
    hours: int = Field(ge=1, le=168)
    dry_run: bool = True


class IncBroadcastRequest(_Body):
    kind: Literal["outage", "restored"]
    dry_run: bool = True


@incidents_router.get("/health", dependencies=_ON + isp_guards(ISP_INCIDENTS_READ))
async def health(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    return ok(request, await svc.health(isp), "Network health")


@incidents_router.get("/preview", dependencies=_ON + isp_guards(ISP_INCIDENTS_MANAGE))
async def preview(
    request: Request,
    scope_kind: ScopeKind,
    isp_router_id: uuid.UUID | None = None,
    fiber_node_id: uuid.UUID | None = None,
    zone_id: uuid.UUID | None = None,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    data = await svc.preview(
        isp,
        scope_kind,
        isp_router_id=isp_router_id,
        fiber_node_id=fiber_node_id,
        zone_id=zone_id,
    )
    return ok(request, data, "Who is affected")


@incidents_router.get("", dependencies=_ON + isp_guards(ISP_INCIDENTS_READ))
async def list_incidents(
    request: Request,
    status: Literal["investigating", "identified", "resolved"] | None = None,
    scope_kind: ScopeKind | None = None,
    open_only: bool = False,
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    data = await svc.list(
        isp,
        status=status,
        scope_kind=scope_kind,
        open_only=open_only,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
    )
    return ok(request, data, "Incidents")


@incidents_router.post(
    "", status_code=201, dependencies=_ON + isp_guards(ISP_INCIDENTS_MANAGE)
)
async def create_incident(
    request: Request,
    body: IncCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    view = await svc.create(isp, body.model_dump())
    await svc.session.commit()
    return ok(request, view, "Incident opened")


@incidents_router.get(
    "/{incident_id}", dependencies=_ON + isp_guards(ISP_INCIDENTS_READ)
)
async def get_incident(
    request: Request,
    incident_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    return ok(request, await svc.detail(isp, incident_id), "Incident")


@incidents_router.post(
    "/{incident_id}/status", dependencies=_ON + isp_guards(ISP_INCIDENTS_MANAGE)
)
async def set_status(
    request: Request,
    incident_id: uuid.UUID,
    body: IncStatusRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    view = await svc.set_status(isp, incident_id, body.model_dump())
    await svc.session.commit()
    return ok(request, view, "Status updated")


@incidents_router.post(
    "/{incident_id}/notes", dependencies=_ON + isp_guards(ISP_INCIDENTS_MANAGE)
)
async def add_note(
    request: Request,
    incident_id: uuid.UUID,
    body: IncNoteRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    view = await svc.add_note(isp, incident_id, body.body)
    await svc.session.commit()
    return ok(request, view, "Note added")


@incidents_router.post(
    "/{incident_id}/refresh", dependencies=_ON + isp_guards(ISP_INCIDENTS_MANAGE)
)
async def refresh(
    request: Request,
    incident_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    view = await svc.refresh(isp, incident_id)
    await svc.session.commit()
    return ok(request, view, "Affected list refreshed")


@incidents_router.post(
    "/{incident_id}/grace", dependencies=_ON + isp_guards(ISP_INCIDENTS_EXECUTE)
)
async def grace(
    request: Request,
    incident_id: uuid.UUID,
    body: IncGraceRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
    rbac: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    from .plans_service import IspPlansService
    from .subscriber360_service import IspSubscriber360Service

    s360 = IspSubscriber360Service(
        plans=IspPlansService(session=svc.session, audit=rbac)
    )
    out = await svc.grace(
        isp, incident_id, hours=body.hours, dry_run=body.dry_run, s360=s360
    )
    if not body.dry_run:
        await svc.session.commit()
    return ok(request, out, "Grace (dry run)" if body.dry_run else "Grace granted")


@incidents_router.post(
    "/{incident_id}/broadcast", dependencies=_ON + isp_guards(ISP_INCIDENTS_EXECUTE)
)
async def broadcast(
    request: Request,
    incident_id: uuid.UUID,
    body: IncBroadcastRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> dict:
    out = await svc.broadcast(isp, incident_id, kind=body.kind, dry_run=body.dry_run)
    if not body.dry_run:
        await svc.session.commit()
    return ok(request, out, "Broadcast")


@incidents_router.get(
    "/{incident_id}/affected.csv",
    dependencies=_ON + isp_guards(ISP_INCIDENTS_EXPORT),
)
async def affected_csv(
    incident_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspIncidentsService = Depends(get_incidents_service),
) -> Response:
    content, name = await svc.affected_csv(isp, incident_id)
    await svc.session.commit()
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


__all__ = ["incidents_router"]

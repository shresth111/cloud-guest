"""SMALL-5 routes, behind INCIDENTS-1's ``ISP_INCIDENTS_ENABLED`` (off ->
404 ``ISP_INCIDENTS_DISABLED``). Own prefix ``/incident-auto`` so nothing is
read as ``/incidents/{incident_id}``.

* ``GET /isp/incident-auto/settings`` (``isp_incidents.read``)
* ``PUT /isp/incident-auto/settings`` (``isp_incidents.manage``; owner /
  admin / noc): ``{enabled, down_minutes 1..240, up_minutes 1..240}``,
  audited.
* ``GET /isp/incident-auto/marks`` (``isp_incidents.read``): the
  auto-opened incidents of routers the caller can see (confinement + header
  zone via ``child_ids``), newest 200, for the "Auto" tag.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository

from . import incident_auto as auto
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .incidents_config import (
    ISP_INCIDENTS_MANAGE,
    ISP_INCIDENTS_READ,
    RequireIncidentsEnabled,
)

incident_auto_router = APIRouter(
    prefix="/incident-auto", tags=["ISP Partner: incidents"]
)
_ON = [Depends(RequireIncidentsEnabled)]


class AutoSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    down_minutes: int | None = Field(default=None, ge=1, le=240)
    up_minutes: int | None = Field(default=None, ge=1, le=240)


@incident_auto_router.get(
    "/settings", dependencies=_ON + isp_guards(ISP_INCIDENTS_READ)
)
async def get_auto_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request,
        auto.settings_view(await auto.get_settings(db, isp.isp_org_id)),
        "Auto incidents",
    )


@incident_auto_router.put(
    "/settings", dependencies=_ON + isp_guards(ISP_INCIDENTS_MANAGE)
)
async def put_auto_settings(
    request: Request,
    payload: AutoSettingsRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit=Depends(get_rbac_repository),  # noqa: ANN001
) -> dict:
    before = auto.settings_view(await auto.get_settings(db, isp.isp_org_id))
    after = await auto.put_settings(db, isp, payload.model_dump(exclude_unset=True))
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action="isp_incident_auto_settings",
        entity_type="isp_incident_auto_settings",
        entity_id=isp.isp_org_id,
        description="ISP auto incident settings changed",
        event_metadata={
            "console": "isp",
            "isp_organization_id": str(isp.isp_org_id),
            "before": before,
            "after": after,
        },
        organization_id=isp.isp_org_id,
        location_id=None,
    )
    return ok(request, after, "Auto incidents saved")


@incident_auto_router.get("/marks", dependencies=_ON + isp_guards(ISP_INCIDENTS_READ))
async def auto_marks(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .incident_auto_models import IspIncidentAuto

    children = await isp.child_ids()
    rows = (
        (
            await db.execute(
                select(IspIncidentAuto)
                .where(
                    IspIncidentAuto.isp_organization_id == isp.isp_org_id,
                    IspIncidentAuto.customer_organization_id.in_(children or [None]),
                )
                .order_by(IspIncidentAuto.opened_at.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    return ok(
        request,
        {
            "items": [
                {
                    "incident_id": str(r.incident_id),
                    "router_id": str(r.router_id),
                    "down_since": r.down_since.isoformat(),
                    "opened_at": r.opened_at.isoformat(),
                    "closed_at": r.closed_at.isoformat() if r.closed_at else None,
                    "auto_resolved": r.auto_resolved,
                    "auto_grace_allowed": not r.auto_resolved,
                }
                for r in rows
            ]
        },
        "Auto incidents",
    )


__all__ = ["incident_auto_router"]

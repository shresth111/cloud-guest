"""DECISIONS-1 (2026-11-10, founder delegated to the coordinator): a franchisee
may add a router at an existing site (location) inside its zones, and nothing
else (no customers, sites, locations, users).

Routes (under ``/isp/workflow``, so behind ``ISP_WORKFLOW_ENABLED``; a
franchisee login itself also needs ``ISP_ZONES_ENABLED``):

* ``GET  /workflow/franchisee/router-sites`` -- the locations the caller may
  add a router to (customer + location names, and the zone the new router
  will be linked to). Drives the console's "Add router" picker.
* ``POST /workflow/franchisee/sites/{site_ref}/routers`` -- registers the
  router through the same ``IspPartnerService.create_router`` the owner's
  ``POST /isp/locations/{isp_location_id}/routers`` uses, then links it to
  the franchisee's zone in ``isp_router_zones``.

Only the ``isp-franchisee`` role may call them (anyone else: 403
``ISP_ROLE_REQUIRED``; owners/admins keep their own route). The guard is the
role's existing ``isp_partner.update`` key: no new RBAC key and no
``isp_partner.create`` grant, so the franchisee still cannot create customers
or locations anywhere.

"Inside its zones" (backend-enforced, a miss is a 404 like any row the caller
cannot see):

* the location belongs to a customer of this ISP that the franchisee scope
  can see (``IspScope.assert_location``: zone customers only), and
* that customer's **profile zone** is in the franchisee's subtree, **or** a
  router already at that location is linked (``isp_router_zones``) to a zone
  in the subtree (a shared site the ISP has said serves this zone).

A customer that is visible only because one of its subscribers sits in the
franchisee's zone (the shared-site read rule) is **not** enough to add
hardware there.

Zone linked to the new router: ``zone_ref`` from the body if given (must be
in the subtree, else 404); otherwise the customer's profile zone when it is
in the subtree, otherwise the first (by name) subtree zone that a router at
the location already serves.

Path ids are never named ``organization_id|customer_id|location_id|
router_id`` (the SCOPE_PARAM_ALIASES trap).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import (
    IspLocationNotFoundError,
    IspRoleRequiredError,
    IspZoneNotFoundError,
)
from .http import ok
from .providers import get_isp_partner_service
from .schemas import IspRouterCreateRequest
from .scoping import IspScope
from .service import IspPartnerService
from .workflow_config import RequireWorkflowEnabled
from .workflow_franchisee import (
    FRANCHISEE_SLUG,
    FranchiseeScope,
    current_franchisee_scope,
)

__all__ = ["franchisee_router_add", "site_zone_for_franchisee"]

PARTNER_UPDATE = "isp_partner.update"

franchisee_router_add = APIRouter(
    prefix="/workflow/franchisee",
    tags=["ISP Partner: workflow"],
    dependencies=[Depends(RequireWorkflowEnabled)],
)


class FranchiseeRouterBody(IspRouterCreateRequest):
    zone_ref: uuid.UUID | None = Field(
        default=None, description="Zone to link the router to (default: the site's)"
    )


def _franchisee(isp: IspContext, session: Any) -> FranchiseeScope:
    scope = current_franchisee_scope(session)
    if getattr(isp, "role_slug", None) != FRANCHISEE_SLUG or scope is None:
        raise IspRoleRequiredError()
    return scope


async def _profile_zone(
    db: Any, isp: IspContext, customer_org_id: uuid.UUID
) -> uuid.UUID | None:
    from .models import IspCustomerProfile

    return (
        await db.execute(
            select(IspCustomerProfile.zone_id).where(
                IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                IspCustomerProfile.customer_organization_id == customer_org_id,
            )
        )
    ).scalar_one_or_none()


async def _linked_zones_at(
    db: Any, isp: IspContext, location_ids: list[uuid.UUID], zone_ids: Any
) -> dict[uuid.UUID, list[uuid.UUID]]:
    """location -> subtree zones (by zone name) served by a router there."""
    from app.domains.router.models import Router

    from .billing_models import IspZone
    from .workflow_models import IspRouterZone

    if not location_ids or not zone_ids:
        return {}
    rows = (
        await db.execute(
            select(Router.location_id, IspRouterZone.zone_id)
            .join(IspRouterZone, IspRouterZone.router_id == Router.id)
            .join(IspZone, IspZone.id == IspRouterZone.zone_id)
            .where(
                Router.location_id.in_(location_ids),
                Router.is_deleted.is_(False),
                IspRouterZone.isp_organization_id == isp.isp_org_id,
                IspRouterZone.is_deleted.is_(False),
                IspRouterZone.zone_id.in_(list(zone_ids)),
                IspZone.is_deleted.is_(False),
            )
            .order_by(IspZone.name)
        )
    ).all()
    out: dict[uuid.UUID, list[uuid.UUID]] = {}
    for loc, zid in rows:
        lst = out.setdefault(loc, [])
        if zid not in lst:
            lst.append(zid)
    return out


async def site_zone_for_franchisee(
    db: Any,
    isp: IspContext,
    scope: FranchiseeScope,
    location: Any,
    zone_ref: uuid.UUID | None = None,
) -> uuid.UUID:
    """The zone a new router at ``location`` is linked to, or 404 when the
    location is not inside the franchisee's zones (see module docstring)."""
    profile = await _profile_zone(db, isp, location.organization_id)
    linked = (await _linked_zones_at(db, isp, [location.id], scope.zone_ids)).get(
        location.id, []
    )
    profile_ok = profile is not None and profile in scope.zone_ids
    if not profile_ok and not linked:
        raise IspLocationNotFoundError()
    if zone_ref is not None:
        if zone_ref not in scope.zone_ids:
            raise IspZoneNotFoundError()
        return zone_ref
    return profile if profile_ok else linked[0]


@franchisee_router_add.get("/router-sites", dependencies=isp_guards(PARTNER_UPDATE))
async def franchisee_router_sites(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization

    from .billing_models import IspZone
    from .models import IspCustomerProfile

    scope = _franchisee(isp, db)
    customers = await isp.child_ids()
    if not customers or not scope.zone_ids:
        return ok(request, {"items": []})
    rows = (
        await db.execute(
            select(Location, Organization.name, IspCustomerProfile.zone_id)
            .join(Organization, Organization.id == Location.organization_id)
            .outerjoin(
                IspCustomerProfile,
                (
                    IspCustomerProfile.customer_organization_id
                    == Location.organization_id
                )
                & (IspCustomerProfile.isp_organization_id == isp.isp_org_id),
            )
            .where(
                Location.organization_id.in_(customers),
                Location.is_deleted.is_(False),
            )
        )
    ).all()
    linked = await _linked_zones_at(db, isp, [r[0].id for r in rows], scope.zone_ids)
    zone_names = {
        z.id: z.name
        for z in (
            await db.execute(select(IspZone).where(IspZone.id.in_(scope.zone_ids)))
        ).scalars()
    }
    items = []
    for loc, org_name, profile_zone in rows:
        if profile_zone is not None and profile_zone in scope.zone_ids:
            zid = profile_zone
        elif linked.get(loc.id):
            zid = linked[loc.id][0]
        else:
            continue
        items.append(
            {
                "isp_customer_id": str(loc.organization_id),
                "customer_name": org_name,
                "isp_location_id": str(loc.id),
                "location_name": loc.name,
                "zone": {"id": str(zid), "name": zone_names.get(zid)},
            }
        )
    items.sort(key=lambda i: (i["customer_name"] or "", i["location_name"] or ""))
    return ok(request, {"items": items})


@franchisee_router_add.post(
    "/sites/{site_ref}/routers",
    status_code=status.HTTP_201_CREATED,
    dependencies=isp_guards(PARTNER_UPDATE),
)
async def franchisee_add_router(
    request: Request,
    site_ref: uuid.UUID,
    payload: FranchiseeRouterBody,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    service: IspPartnerService = Depends(get_isp_partner_service),
) -> dict:
    from .billing_models import IspZone
    from .workflow_models import IspRouterZone

    scope = _franchisee(isp, db)
    location = await IspScope.assert_location(isp, site_ref)
    zone_id = await site_zone_for_franchisee(db, isp, scope, location, payload.zone_ref)
    body = payload.model_dump(exclude={"zone_ref", "ip_logs"})
    data = await service.create_router(isp, location.id, body)
    # DEFAULT-LOGS: the Add router IP-logs switch (no-op when not sent).
    from .iplogs_default import record_add_router_choice

    data = await record_add_router_choice(db, isp, data, payload.ip_logs)
    db.add(
        IspRouterZone(
            isp_organization_id=isp.isp_org_id,
            router_id=uuid.UUID(str(data["id"])),
            zone_id=zone_id,
            created_by=isp.user_id,
        )
    )
    await db.commit()
    zone = await db.get(IspZone, zone_id)
    data = {
        **data,
        "zones": [{"id": str(zone_id), "name": getattr(zone, "name", None)}],
    }
    return ok(request, data, "Router registered")

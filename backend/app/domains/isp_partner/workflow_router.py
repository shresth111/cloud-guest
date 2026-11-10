"""RAKESH-FS: ``/isp/workflow`` (flag ``ISP_WORKFLOW_ENABLED``, default OFF).

Zone -> Router -> Subscriber -> Package, end to end:

* ``GET /workflow/features`` -- what the console may switch on.
* ``GET /workflow/me`` -- the caller's role and, for a franchisee, its zones.
* ``GET /workflow/franchisees`` / ``GET|PUT /workflow/franchisees/{user_ref}/zones``
  -- owner/admin (``isp_partner.assign``) assign a franchisee user's zones.
  The user itself is created by the existing ``POST /isp/users`` with role
  ``isp-franchisee``.
* ``GET|PUT /workflow/routers/{device_ref}/zones`` -- the zones one router
  serves (several zones may share it). PUT needs ``isp_zones.manage``.
* ``GET /workflow/zones/{zone_ref}/routers`` -- routers serving a zone.
* ``GET /workflow/placement?zone_ref=`` -- for onboarding: the routers (with
  their customer + location) that serve the zone, nearest first, and the one
  to pre-select.
* ``GET|PUT /workflow/subscribers/{sub_ref}/router`` -- the router a
  subscriber is placed on (must be one of its own customer's routers).
* ``GET|PUT /workflow/zones/{zone_ref}/packages`` -- the packages a zone may
  sell (empty = all). Enforced for franchisees in ``workflow_franchisee``.

Path ids are never named ``organization_id|customer_id|location_id|
router_id`` (the SCOPE_PARAM_ALIASES trap).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import (
    IspRouterNotFoundError,
    IspUserNotFoundError,
    IspZoneNotFoundError,
)
from .http import ok
from .plans_service import IspPackageNotFoundError, IspSubscriberNotFoundError
from .scoping import IspScope
from .workflow_config import MB_PER_GB, RequireWorkflowEnabled, franchisee_logins_on
from .workflow_franchisee import FRANCHISEE_SLUG, current_franchisee_scope

__all__ = ["workflow_router"]

PARTNER_READ = "isp_partner.read"
PARTNER_ASSIGN = "isp_partner.assign"
ZONES_READ = "isp_zones.read"
ZONES_MANAGE = "isp_zones.manage"
SUBS_READ = "isp_subscribers.read"
SUBS_UPDATE = "isp_subscribers.update"
PLANS_READ = "isp_plans.read"

workflow_router = APIRouter(
    prefix="/workflow",
    tags=["ISP Partner: workflow"],
    dependencies=[Depends(RequireWorkflowEnabled)],
)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ZoneSetBody(_Body):
    zone_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)


class PackageSetBody(_Body):
    package_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)


class RouterBody(_Body):
    isp_router_id: uuid.UUID | None = None


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _zones(db: Any, isp: IspContext, ids: list[uuid.UUID]) -> list[Any]:
    """This ISP's live zones for ``ids`` (a franchisee sees only its own);
    any unknown id -> 404."""
    from .billing_models import IspZone

    wanted = list(dict.fromkeys(ids))
    if not wanted:
        return []
    rows = list(
        (
            await db.execute(
                select(IspZone).where(
                    IspZone.id.in_(wanted),
                    IspZone.isp_organization_id == isp.isp_org_id,
                    IspZone.is_deleted.is_(False),
                )
            )
        ).scalars()
    )
    if len(rows) != len(wanted):
        raise IspZoneNotFoundError()
    order = {z: i for i, z in enumerate(wanted)}
    return sorted(rows, key=lambda z: order[z.id])


async def _zone(db: Any, isp: IspContext, zone_ref: uuid.UUID) -> Any:
    return (await _zones(db, isp, [zone_ref]))[0]


def _zone_view(z: Any) -> dict:
    return {"id": str(z.id), "name": z.name, "city": z.city}


async def _router_rows(
    db: Any, isp: IspContext, router_ids: set[uuid.UUID]
) -> list[dict]:
    """Visible routers (confinement honoured) with customer + location names."""
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization
    from app.domains.router.models import Router

    if not router_ids:
        return []
    children = set(await isp.child_ids())
    rows = (
        await db.execute(
            select(Router, Location.name, Organization.name)
            .join(Location, Location.id == Router.location_id)
            .join(Organization, Organization.id == Router.organization_id)
            .where(Router.id.in_(router_ids), Router.is_deleted.is_(False))
        )
    ).all()
    out = []
    for r, loc_name, org_name in rows:
        if r.organization_id not in children:
            continue
        out.append(
            {
                "isp_router_id": str(r.id),
                "name": r.name,
                "status": getattr(r, "status", None),
                "isp_customer_id": str(r.organization_id),
                "customer_name": org_name,
                "isp_location_id": str(r.location_id),
                "location_name": loc_name,
            }
        )
    return sorted(out, key=lambda x: (x["customer_name"] or "", x["name"] or ""))


async def _subscriber(db: Any, isp: IspContext, sub_ref: uuid.UUID) -> Any:
    from .plans_models import IspSubscriber

    s = (
        await db.execute(
            select(IspSubscriber).where(
                IspSubscriber.id == sub_ref,
                IspSubscriber.isp_organization_id == isp.isp_org_id,
                IspSubscriber.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if s is None or s.customer_organization_id not in set(await isp.child_ids()):
        raise IspSubscriberNotFoundError()
    return s


async def _franchisee_user(isp: IspContext, user_ref: uuid.UUID) -> None:
    rows = await isp.repository.isp_role_assignments(isp.isp_org_id, user_id=user_ref)
    if not any(role.slug == FRANCHISEE_SLUG for _, role in rows):
        raise IspUserNotFoundError()


# --------------------------------------------------------------------------
# features / me
# --------------------------------------------------------------------------


@workflow_router.get("/features", dependencies=isp_guards(PARTNER_READ))
async def workflow_features(
    request: Request, isp: IspContext = Depends(RequireIspPartner)
) -> dict:
    return ok(
        request,
        {
            "data_limit_unit": "GB",
            "mb_per_gb": MB_PER_GB,
            "router_zones": True,
            "auto_placement": True,
            "franchisee_logins": franchisee_logins_on(),
            "is_franchisee": isp.role_slug == FRANCHISEE_SLUG,
        },
    )


@workflow_router.get("/me", dependencies=isp_guards(PARTNER_READ))
async def workflow_me(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .billing_models import IspZone
    from .workflow_franchisee import franchisee_root_zones

    zones: list[dict] = []
    if isp.role_slug == FRANCHISEE_SLUG:
        roots = await franchisee_root_zones(db, isp.isp_org_id, isp.user_id)
        if roots:
            rows = (
                await db.execute(
                    select(IspZone).where(
                        IspZone.id.in_(roots), IspZone.is_deleted.is_(False)
                    )
                )
            ).scalars()
            zones = [_zone_view(z) for z in rows]
    scope = current_franchisee_scope(db)
    return ok(
        request,
        {
            "role": isp.role_slug,
            "is_franchisee": isp.role_slug == FRANCHISEE_SLUG,
            "zones": zones,
            "zone_count_in_scope": len(scope.zone_ids) if scope else None,
            "package_allowlist": (
                sorted(str(p) for p in scope.package_ids)
                if scope and scope.package_ids is not None
                else None
            ),
        },
    )


# --------------------------------------------------------------------------
# franchisee zones (owner/admin)
# --------------------------------------------------------------------------


@workflow_router.get("/franchisees", dependencies=isp_guards(PARTNER_ASSIGN))
async def list_franchisees(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .billing_models import IspZone
    from .workflow_models import IspFranchiseeZone

    rows = await isp.repository.isp_role_assignments(isp.isp_org_id)
    user_ids = [a.user_id for a, role in rows if role.slug == FRANCHISEE_SLUG]
    zones: dict[uuid.UUID, list[dict]] = {u: [] for u in user_ids}
    if user_ids:
        for uid, z in (
            await db.execute(
                select(IspFranchiseeZone.user_id, IspZone)
                .join(IspZone, IspZone.id == IspFranchiseeZone.zone_id)
                .where(
                    IspFranchiseeZone.isp_organization_id == isp.isp_org_id,
                    IspFranchiseeZone.user_id.in_(user_ids),
                    IspFranchiseeZone.is_deleted.is_(False),
                    IspZone.is_deleted.is_(False),
                )
            )
        ).all():
            zones[uid].append(_zone_view(z))
    items = []
    for uid in user_ids:
        u = await isp.repository.get_user(uid)
        items.append(
            {
                "user_id": str(uid),
                "email": getattr(u, "email", None),
                "full_name": getattr(u, "full_name", None) or getattr(u, "name", None),
                "zones": zones[uid],
            }
        )
    return ok(request, {"items": items, "enabled": franchisee_logins_on()})


@workflow_router.get(
    "/franchisees/{user_ref}/zones", dependencies=isp_guards(PARTNER_ASSIGN)
)
async def get_franchisee_zones(
    request: Request,
    user_ref: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .workflow_franchisee import franchisee_root_zones

    await _franchisee_user(isp, user_ref)
    roots = await franchisee_root_zones(db, isp.isp_org_id, user_ref)
    zones = await _zones(db, isp, roots) if roots else []
    return ok(
        request, {"user_id": str(user_ref), "zones": [_zone_view(z) for z in zones]}
    )


@workflow_router.put(
    "/franchisees/{user_ref}/zones", dependencies=isp_guards(PARTNER_ASSIGN)
)
async def put_franchisee_zones(
    request: Request,
    user_ref: uuid.UUID,
    body: ZoneSetBody,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .workflow_models import IspFranchiseeZone

    await _franchisee_user(isp, user_ref)
    zones = await _zones(db, isp, body.zone_ids)
    await db.execute(
        delete(IspFranchiseeZone).where(
            IspFranchiseeZone.isp_organization_id == isp.isp_org_id,
            IspFranchiseeZone.user_id == user_ref,
        )
    )
    for z in zones:
        db.add(
            IspFranchiseeZone(
                isp_organization_id=isp.isp_org_id,
                user_id=user_ref,
                zone_id=z.id,
                created_by=isp.user_id,
            )
        )
    await db.commit()
    return ok(
        request,
        {"user_id": str(user_ref), "zones": [_zone_view(z) for z in zones]},
        "Franchisee zones saved",
    )


# --------------------------------------------------------------------------
# router <-> zones
# --------------------------------------------------------------------------


async def _router_zone_rows(db: Any, isp: IspContext, rid: uuid.UUID) -> list[Any]:
    from .billing_models import IspZone
    from .workflow_models import IspRouterZone

    return list(
        (
            await db.execute(
                select(IspZone)
                .join(IspRouterZone, IspRouterZone.zone_id == IspZone.id)
                .where(
                    IspRouterZone.router_id == rid,
                    IspRouterZone.isp_organization_id == isp.isp_org_id,
                    IspRouterZone.is_deleted.is_(False),
                    IspZone.is_deleted.is_(False),
                )
                .order_by(IspZone.name)
            )
        ).scalars()
    )


@workflow_router.get(
    "/routers/{device_ref}/zones", dependencies=isp_guards(PARTNER_READ)
)
async def get_router_zones(
    request: Request,
    device_ref: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    await IspScope.assert_router(isp, device_ref)
    zones = await _router_zone_rows(db, isp, device_ref)
    return ok(
        request,
        {"isp_router_id": str(device_ref), "zones": [_zone_view(z) for z in zones]},
    )


@workflow_router.put(
    "/routers/{device_ref}/zones", dependencies=isp_guards(ZONES_MANAGE)
)
async def put_router_zones(
    request: Request,
    device_ref: uuid.UUID,
    body: ZoneSetBody,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .workflow_models import IspRouterZone

    router = await IspScope.assert_router(isp, device_ref)
    zones = await _zones(db, isp, body.zone_ids)
    await db.execute(
        delete(IspRouterZone).where(
            IspRouterZone.isp_organization_id == isp.isp_org_id,
            IspRouterZone.router_id == router.id,
        )
    )
    for z in zones:
        db.add(
            IspRouterZone(
                isp_organization_id=isp.isp_org_id,
                router_id=router.id,
                zone_id=z.id,
                created_by=isp.user_id,
            )
        )
    await db.commit()
    return ok(
        request,
        {"isp_router_id": str(router.id), "zones": [_zone_view(z) for z in zones]},
        "Router zones saved",
    )


async def _routers_for_zones(
    db: Any, isp: IspContext, zone_ids: list[uuid.UUID]
) -> list[Any]:
    from .workflow_models import IspRouterZone

    if not zone_ids:
        return []
    return list(
        (
            await db.execute(
                select(IspRouterZone.router_id, IspRouterZone.zone_id).where(
                    IspRouterZone.isp_organization_id == isp.isp_org_id,
                    IspRouterZone.zone_id.in_(zone_ids),
                    IspRouterZone.is_deleted.is_(False),
                )
            )
        ).all()
    )


@workflow_router.get("/zones/{zone_ref}/routers", dependencies=isp_guards(ZONES_READ))
async def get_zone_routers(
    request: Request,
    zone_ref: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    z = await _zone(db, isp, zone_ref)
    links = await _routers_for_zones(db, isp, [z.id])
    items = await _router_rows(db, isp, {r for r, _ in links})
    return ok(request, {"zone": _zone_view(z), "items": items})


# --------------------------------------------------------------------------
# placement (onboarding auto-assign)
# --------------------------------------------------------------------------


@workflow_router.get("/placement", dependencies=isp_guards(SUBS_UPDATE))
async def placement(
    request: Request,
    zone_ref: uuid.UUID = Query(...),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Routers for a new subscriber in ``zone_ref``, nearest zone first:
    routers linked to the zone itself, then to its parent, and so on; then
    routers of customers whose profile zone is on that path. ``suggested``
    is the first one (the form pre-selects it and the customer it is at)."""
    from app.domains.router.models import Router

    from .models import IspCustomerProfile
    from .zones_scope import ancestry, parent_map, zone_rows

    z = await _zone(db, isp, zone_ref)
    parents = parent_map(await zone_rows(db, isp.isp_org_id))
    path = list(reversed(ancestry(parents, z.id)))  # zone first, root last
    rank: dict[uuid.UUID, tuple[int, str]] = {}
    for rid, zid in await _routers_for_zones(db, isp, path):
        r = (path.index(zid), "linked")
        if rid not in rank or r < rank[rid]:
            rank[rid] = r
    prof = (
        await db.execute(
            select(
                IspCustomerProfile.customer_organization_id, IspCustomerProfile.zone_id
            ).where(
                IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                IspCustomerProfile.zone_id.in_(path),
            )
        )
    ).all()
    if prof:
        cust_depth = {c: path.index(zid) for c, zid in prof}
        for rid, cid in (
            await db.execute(
                select(Router.id, Router.organization_id).where(
                    Router.organization_id.in_(list(cust_depth)),
                    Router.is_deleted.is_(False),
                )
            )
        ).all():
            r = (len(path) + cust_depth[cid], "customer_zone")
            if rid not in rank:
                rank[rid] = r
    items = await _router_rows(db, isp, set(rank))
    for it in items:
        depth, how = rank[uuid.UUID(it["isp_router_id"])]
        it["match"] = how
        it["distance"] = depth
    items.sort(
        key=lambda x: (x["match"] != "linked", x["distance"], x["customer_name"] or "")
    )
    return ok(
        request,
        {
            "zone": _zone_view(z),
            "items": items,
            "suggested": items[0] if items else None,
        },
    )


# --------------------------------------------------------------------------
# subscriber router
# --------------------------------------------------------------------------


async def _subscriber_router_view(db: Any, isp: IspContext, s: Any) -> dict:
    from .workflow_models import IspSubscriberRouter

    link = (
        await db.execute(
            select(IspSubscriberRouter).where(
                IspSubscriberRouter.subscriber_id == s.id,
                IspSubscriberRouter.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    rows = await _router_rows(db, isp, {link.router_id}) if link else []
    return {"subscriber_id": str(s.id), "router": rows[0] if rows else None}


@workflow_router.get(
    "/subscribers/{sub_ref}/router", dependencies=isp_guards(SUBS_READ)
)
async def get_subscriber_router(
    request: Request,
    sub_ref: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    s = await _subscriber(db, isp, sub_ref)
    return ok(request, await _subscriber_router_view(db, isp, s))


@workflow_router.put(
    "/subscribers/{sub_ref}/router", dependencies=isp_guards(SUBS_UPDATE)
)
async def put_subscriber_router(
    request: Request,
    sub_ref: uuid.UUID,
    body: RouterBody,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .workflow_models import IspSubscriberRouter

    s = await _subscriber(db, isp, sub_ref)
    if body.isp_router_id is not None:
        router = await IspScope.assert_router(isp, body.isp_router_id)
        if router.organization_id != s.customer_organization_id:
            # a subscriber can only be on one of its own customer's routers
            raise IspRouterNotFoundError()
    await db.execute(
        delete(IspSubscriberRouter).where(IspSubscriberRouter.subscriber_id == s.id)
    )
    if body.isp_router_id is not None:
        db.add(
            IspSubscriberRouter(
                isp_organization_id=isp.isp_org_id,
                subscriber_id=s.id,
                router_id=body.isp_router_id,
                created_by=isp.user_id,
            )
        )
    await db.commit()
    return ok(request, await _subscriber_router_view(db, isp, s), "Router saved")


# --------------------------------------------------------------------------
# zone packages (what a zone may sell)
# --------------------------------------------------------------------------


async def _zone_packages(db: Any, isp: IspContext, zid: uuid.UUID) -> list[Any]:
    from .plans_models import IspPackage
    from .workflow_models import IspZonePackage

    return list(
        (
            await db.execute(
                select(IspPackage)
                .join(IspZonePackage, IspZonePackage.package_id == IspPackage.id)
                .where(
                    IspZonePackage.zone_id == zid,
                    IspZonePackage.isp_organization_id == isp.isp_org_id,
                    IspZonePackage.is_deleted.is_(False),
                    IspPackage.is_deleted.is_(False),
                )
                .order_by(IspPackage.name)
            )
        ).scalars()
    )


def _pkg_view(p: Any) -> dict:
    return {"id": str(p.id), "name": p.name, "data_cap_mb": p.data_cap_mb}


@workflow_router.get("/zones/{zone_ref}/packages", dependencies=isp_guards(PLANS_READ))
async def get_zone_packages(
    request: Request,
    zone_ref: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    z = await _zone(db, isp, zone_ref)
    pkgs = await _zone_packages(db, isp, z.id)
    return ok(
        request,
        {
            "zone": _zone_view(z),
            "all_packages": not pkgs,
            "items": [_pkg_view(p) for p in pkgs],
        },
    )


@workflow_router.put(
    "/zones/{zone_ref}/packages", dependencies=isp_guards(ZONES_MANAGE)
)
async def put_zone_packages(
    request: Request,
    zone_ref: uuid.UUID,
    body: PackageSetBody,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .plans_models import IspPackage
    from .workflow_models import IspZonePackage

    z = await _zone(db, isp, zone_ref)
    wanted = list(dict.fromkeys(body.package_ids))
    if wanted:
        found = set(
            (
                await db.execute(
                    select(IspPackage.id).where(
                        IspPackage.id.in_(wanted),
                        IspPackage.isp_organization_id == isp.isp_org_id,
                        IspPackage.is_deleted.is_(False),
                    )
                )
            ).scalars()
        )
        if found != set(wanted):
            raise IspPackageNotFoundError()
    await db.execute(
        delete(IspZonePackage).where(
            IspZonePackage.isp_organization_id == isp.isp_org_id,
            IspZonePackage.zone_id == z.id,
        )
    )
    for pid in wanted:
        db.add(
            IspZonePackage(
                isp_organization_id=isp.isp_org_id,
                zone_id=z.id,
                package_id=pid,
                created_by=isp.user_id,
            )
        )
    await db.commit()
    pkgs = await _zone_packages(db, isp, z.id)
    return ok(
        request,
        {
            "zone": _zone_view(z),
            "all_packages": not pkgs,
            "items": [_pkg_view(p) for p in pkgs],
        },
        "Zone packages saved",
    )

"""P1-3: per-zone "may generate coupons" right for franchisees.

Flag ``ISP_ZONE_COUPON_RIGHTS_ENABLED`` (default OFF: routes 404, gate is
identity). The right is hierarchical: a zone's explicit row wins; no row =
the nearest ancestor's explicit row; no explicit row on the whole path =
allowed (what the RAKESH-FS franchisee role does today). It applies only to
the ``isp-franchisee`` role; owner/admin/billing/... are never gated here.

The zone checked is the target customer's profile zone (the one RAKESH-FS
uses to put a customer inside a franchisee's subtree). A customer with no
zone is not gated (the franchisee scope already decides whether it is
visible at all).

* ``GET /zone-coupon-rights`` -> explicit rows of this ISP (isp_zones.read).
* ``GET /zones/{zone_id}/coupon-right`` -> explicit + effective value.
* ``PUT /zones/{zone_id}/coupon-right`` ``{"allow_generate": true|false|null}``
  (isp_zones.manage = owner/admin); ``null`` removes the row (= inherit).

The tree is read with plain SQL so a franchisee's own zone narrowing (ORM
criteria on ``isp_zones``) cannot hide the ancestors that decide its right.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .constants import ISP_ZONES_MANAGE, ISP_ZONES_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspFeatureDisabledError, IspZoneNotFoundError, _err
from .http import ok
from .p1_config import get_p1_settings
from .p1_models import IspZoneCouponRight

__all__ = [
    "FRANCHISEE_SLUG",
    "IspCouponsNotPermittedError",
    "coupon_gate",
    "effective_right",
    "p1_coupon_rights_router",
]

#: RAKESH-FS role slug (``workflow_franchisee.FRANCHISEE_SLUG``).
FRANCHISEE_SLUG = "isp-franchisee"

IspCouponsNotPermittedError = _err(
    "IspCouponsNotPermittedError",
    "ISP_COUPONS_NOT_PERMITTED",
    403,
    "Coupon generation is not permitted in this zone",
)


async def _tree(
    session: Any, isp_org_id: uuid.UUID
) -> dict[uuid.UUID, uuid.UUID | None]:
    rows = (
        await session.execute(
            text(
                "SELECT z.id, n.parent_zone_id FROM isp_zones z "
                "LEFT JOIN isp_zone_nodes n "
                "ON n.zone_id = z.id AND n.is_deleted = false "
                "WHERE z.isp_organization_id = :isp AND z.is_deleted = false"
            ),
            {"isp": isp_org_id},
        )
    ).all()
    ids = {r[0] for r in rows}
    return {r[0]: (r[1] if r[1] in ids and r[1] != r[0] else None) for r in rows}


async def _explicit(session: Any, isp_org_id: uuid.UUID) -> dict[uuid.UUID, bool]:
    rows = (
        await session.execute(
            text(
                "SELECT zone_id, allow_generate FROM isp_zone_coupon_rights "
                "WHERE isp_organization_id = :isp AND is_deleted = false"
            ),
            {"isp": isp_org_id},
        )
    ).all()
    return {r[0]: bool(r[1]) for r in rows}


def effective_right(
    parents: dict[uuid.UUID, uuid.UUID | None],
    explicit: dict[uuid.UUID, bool],
    zone_id: uuid.UUID,
) -> tuple[bool, uuid.UUID | None]:
    """(allowed, zone whose row decided it or None for the default)."""
    seen: set[uuid.UUID] = set()
    cur: uuid.UUID | None = zone_id
    while cur is not None and cur not in seen:
        seen.add(cur)
        if cur in explicit:
            return explicit[cur], cur
        cur = parents.get(cur)
    return True, None


async def coupon_gate(session: Any, isp: Any, customer_id: uuid.UUID | None) -> None:
    """Called once from ``create_coupon_batch``. Identity unless the flag is
    on and the caller is a franchisee; then 403 where the zone says no."""
    if not get_p1_settings().zone_coupon_rights_enabled:
        return
    if getattr(isp, "role_slug", None) != FRANCHISEE_SLUG or customer_id is None:
        return
    from .scoping import IspScope

    # an invisible customer stays the usual 404, never a 403 that leaks it
    await IspScope.assert_customer(isp, customer_id)
    zone_id = (
        await session.execute(
            text(
                "SELECT zone_id FROM isp_customer_profiles "
                "WHERE customer_organization_id = :c AND isp_organization_id = :isp "
                "AND is_deleted = false"
            ),
            {"c": customer_id, "isp": isp.isp_org_id},
        )
    ).scalar_one_or_none()
    if zone_id is None:
        return
    allowed, _by = effective_right(
        await _tree(session, isp.isp_org_id),
        await _explicit(session, isp.isp_org_id),
        zone_id,
    )
    if not allowed:
        raise IspCouponsNotPermittedError()


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


async def RequireZoneCouponRightsEnabled() -> None:
    if not get_p1_settings().zone_coupon_rights_enabled:
        raise IspFeatureDisabledError()


p1_coupon_rights_router = APIRouter(
    tags=["ISP Partner: zone coupon rights"],
    dependencies=[Depends(RequireZoneCouponRightsEnabled)],
)


class CouponRightRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: None = remove the explicit row (inherit from the parent zone)
    allow_generate: bool | None


async def _zone_view(
    db: AsyncSession, isp: IspContext, zone_id: uuid.UUID
) -> dict[str, Any]:
    parents = await _tree(db, isp.isp_org_id)
    if zone_id not in parents:
        raise IspZoneNotFoundError()
    await _visible_zone(db, isp, zone_id)
    explicit = await _explicit(db, isp.isp_org_id)
    allowed, by = effective_right(parents, explicit, zone_id)
    return {
        "zone_id": str(zone_id),
        "explicit": explicit.get(zone_id),
        "allow_generate": allowed,
        "decided_by_zone_id": str(by) if by else None,
    }


async def _visible_zone(db: AsyncSession, isp: IspContext, zone_id: uuid.UUID) -> None:
    """ORM read: a zone the caller's own scope hides is a 404 like any other."""
    from .billing_models import IspZone

    row = (
        await db.execute(
            select(IspZone.id).where(
                IspZone.id == zone_id,
                IspZone.isp_organization_id == isp.isp_org_id,
                IspZone.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise IspZoneNotFoundError()


@p1_coupon_rights_router.get(
    "/zone-coupon-rights", dependencies=isp_guards(ISP_ZONES_READ)
)
async def list_coupon_rights(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    parents = await _tree(db, isp.isp_org_id)
    explicit = await _explicit(db, isp.isp_org_id)
    from .billing_models import IspZone

    visible = set(
        (
            await db.execute(
                select(IspZone.id).where(
                    IspZone.isp_organization_id == isp.isp_org_id,
                    IspZone.is_deleted.is_(False),
                )
            )
        ).scalars()
    )
    items = []
    for zid in sorted(visible, key=str):
        allowed, by = effective_right(parents, explicit, zid)
        items.append(
            {
                "zone_id": str(zid),
                "explicit": explicit.get(zid),
                "allow_generate": allowed,
                "decided_by_zone_id": str(by) if by else None,
            }
        )
    return ok(request, {"items": items}, "Zone coupon rights")


@p1_coupon_rights_router.get(
    "/zones/{zone_id}/coupon-right", dependencies=isp_guards(ISP_ZONES_READ)
)
async def get_coupon_right(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(request, await _zone_view(db, isp, zone_id), "Zone coupon right")


@p1_coupon_rights_router.put(
    "/zones/{zone_id}/coupon-right", dependencies=isp_guards(ISP_ZONES_MANAGE)
)
async def put_coupon_right(
    request: Request,
    zone_id: uuid.UUID,
    payload: CouponRightRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    await _zone_view(db, isp, zone_id)  # 404 first
    row = (
        await db.execute(
            select(IspZoneCouponRight).where(
                IspZoneCouponRight.zone_id == zone_id,
                IspZoneCouponRight.isp_organization_id == isp.isp_org_id,
                IspZoneCouponRight.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if payload.allow_generate is None:
        if row is not None:
            await db.delete(row)
    else:
        if row is None:
            row = IspZoneCouponRight(
                isp_organization_id=isp.isp_org_id,
                zone_id=zone_id,
                allow_generate=payload.allow_generate,
                created_by=isp.user_id,
            )
            db.add(row)
        row.allow_generate = payload.allow_generate
        row.updated_by = isp.user_id
    await db.flush()
    await db.commit()
    return ok(request, await _zone_view(db, isp, zone_id), "Zone coupon right saved")

"""ZONE-1 routes: the zone tree, its totals, and nothing that logs a zone in.

Contract: LANE_NOTES [ZONE-1]. Every route is behind ``ISP_ZONES_ENABLED``
(404 ``ISP_ZONES_DISABLED`` while off) and the standard ``/isp`` guards.
Rename stays the existing ``PATCH /isp/zones/{zone_id}``; zone details stay
JAZE-4's ``/isp/finance/zones/{zone_id}/profile``.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .billing_service import IspBillingService
from .constants import ISP_ZONES_MANAGE, ISP_ZONES_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspZoneInUseError, IspZoneNotFoundError
from .http import ok
from .zones_config import (
    IspZoneCycleError,
    IspZoneHasChildrenError,
    RequireZonesEnabled,
)
from .zones_scope import ancestry, descendants, lock_tree, parent_map, zone_rows

zones_router = APIRouter(tags=["ISP Partner: zone tree"])
_ON = [Depends(RequireZonesEnabled)]


def get_billing(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspBillingService:
    return IspBillingService(session=db, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ZoneCreateRequest(_Body):
    name: str = Field(min_length=1, max_length=100)
    parent_id: uuid.UUID | None = None
    city: str | None = Field(default=None, max_length=100)
    state_code: str | None = Field(default=None, pattern=r"^\d{2}$")
    notes: str | None = Field(default=None, max_length=2000)


class ZoneParentRequest(_Body):
    parent_id: uuid.UUID | None


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _counts(
    db: AsyncSession, isp: IspContext
) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, int], dict[uuid.UUID, int]]:
    """Per zone: customers (profile zone), subscribers (own zone), invoices.
    Confinement applies to customers and subscribers."""
    from .billing_models import IspInvoice
    from .models import IspCustomerProfile
    from .plans_models import IspSubscriber

    children = await isp.child_ids()
    if not children:
        return {}, {}, {}
    cust = dict(
        (
            await db.execute(
                select(IspCustomerProfile.zone_id, func.count())
                .where(
                    IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                    IspCustomerProfile.zone_id.is_not(None),
                    IspCustomerProfile.customer_organization_id.in_(children),
                )
                .group_by(IspCustomerProfile.zone_id)
            )
        ).all()
    )
    subs = dict(
        (
            await db.execute(
                select(IspSubscriber.zone_id, func.count())
                .where(
                    IspSubscriber.isp_organization_id == isp.isp_org_id,
                    IspSubscriber.zone_id.is_not(None),
                    IspSubscriber.is_deleted.is_(False),
                    IspSubscriber.customer_organization_id.in_(children),
                )
                .group_by(IspSubscriber.zone_id)
            )
        ).all()
    )
    inv = dict(
        (
            await db.execute(
                select(IspInvoice.zone_id, func.count())
                .where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.zone_id.is_not(None),
                )
                .group_by(IspInvoice.zone_id)
            )
        ).all()
    )
    return cust, subs, inv


async def _all_member_counts(
    db: AsyncSession, isp: IspContext, zone_id: uuid.UUID
) -> tuple[int, int]:
    """Customers and subscribers in one zone, NOT confined: a confined caller
    must not delete a zone that holds customers it cannot see."""
    from .models import IspCustomerProfile
    from .plans_models import IspSubscriber

    customers = (
        await db.execute(
            select(func.count()).where(
                IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                IspCustomerProfile.zone_id == zone_id,
            )
        )
    ).scalar_one()
    subscribers = (
        await db.execute(
            select(func.count()).where(
                IspSubscriber.isp_organization_id == isp.isp_org_id,
                IspSubscriber.zone_id == zone_id,
                IspSubscriber.is_deleted.is_(False),
            )
        )
    ).scalar_one()
    return int(customers), int(subscribers)


def _subtree_sum(
    parents: dict[uuid.UUID, uuid.UUID | None],
    counts: dict[uuid.UUID, int],
    zid: uuid.UUID,
) -> int:
    return sum(counts.get(z, 0) for z in descendants(parents, zid))


async def tree_payload(db: AsyncSession, isp: IspContext) -> list[dict[str, Any]]:
    rows = await zone_rows(db, isp.isp_org_id)
    parents = parent_map(rows)
    zones = {z.id: z for z, _ in rows}
    cust, subs, inv = await _counts(db, isp)
    kids: dict[uuid.UUID | None, list[uuid.UUID]] = {}
    for zid, p in parents.items():
        kids.setdefault(p, []).append(zid)
    for v in kids.values():
        v.sort(key=lambda i: zones[i].name.lower())

    out: list[dict[str, Any]] = []
    seen: set[uuid.UUID] = set()

    def view(zid: uuid.UUID) -> dict[str, Any]:
        z = zones[zid]
        path = ancestry(parents, zid)
        n_children = len(kids.get(zid, []))
        return {
            "id": str(zid),
            "name": z.name,
            "parent_id": str(parents[zid]) if parents[zid] else None,
            "depth": len(path) - 1,
            "path_ids": [str(p) for p in path],
            "path_names": [zones[p].name for p in path],
            "city": z.city,
            "state_code": z.state_code,
            "children": n_children,
            "customers": cust.get(zid, 0),
            "subscribers": subs.get(zid, 0),
            "subtree_customers": _subtree_sum(parents, cust, zid),
            "subtree_subscribers": _subtree_sum(parents, subs, zid),
            "can_delete": n_children == 0
            and not cust.get(zid)
            and not subs.get(zid)
            and not inv.get(zid),
        }

    def walk(p: uuid.UUID | None) -> None:
        for zid in kids.get(p, []):
            if zid in seen:
                continue
            seen.add(zid)
            out.append(view(zid))
            walk(zid)

    walk(None)
    for zid in parents:  # only reachable through a stored cycle
        if zid not in seen:
            seen.add(zid)
            out.append(view(zid))
    return out


async def _node_view(db: AsyncSession, isp: IspContext, zone_id: uuid.UUID) -> dict:
    for n in await tree_payload(db, isp):
        if n["id"] == str(zone_id):
            return n
    raise IspZoneNotFoundError()


async def _set_parent(
    db: AsyncSession, isp: IspContext, zone_id: uuid.UUID, parent_id: uuid.UUID | None
) -> None:
    from .zones_models import IspZoneNode

    await lock_tree(db, isp.isp_org_id)
    parents = parent_map(await zone_rows(db, isp.isp_org_id))
    if zone_id not in parents:
        raise IspZoneNotFoundError()
    if parent_id is not None:
        if parent_id not in parents:
            raise IspZoneNotFoundError()  # another ISP's, deleted, or unknown
        if parent_id in descendants(parents, zone_id):
            raise IspZoneCycleError()
    node = (
        await db.execute(
            select(IspZoneNode).where(
                IspZoneNode.zone_id == zone_id, IspZoneNode.is_deleted.is_(False)
            )
        )
    ).scalar_one_or_none()
    if node is None:
        node = IspZoneNode(
            isp_organization_id=isp.isp_org_id, zone_id=zone_id, created_by=isp.user_id
        )
        db.add(node)
    node.parent_zone_id = parent_id
    node.updated_by = isp.user_id
    await db.flush()


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------


@zones_router.get("/zones/tree", dependencies=_ON + isp_guards(ISP_ZONES_READ))
async def get_zone_tree(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .finance_config import get_finance_settings

    return ok(
        request,
        {
            "items": await tree_payload(db, isp),
            "ledger_enabled": get_finance_settings().zone_ledger_enabled,
        },
        "Zone tree",
    )


@zones_router.post(
    "/zones/tree", status_code=201, dependencies=_ON + isp_guards(ISP_ZONES_MANAGE)
)
async def create_tree_zone(
    request: Request,
    payload: ZoneCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspBillingService = Depends(get_billing),
) -> dict:
    data = payload.model_dump(exclude={"parent_id"})
    if payload.parent_id is not None:
        await svc.zone(isp, payload.parent_id)  # 404 before anything is written
    created = await svc.create_zone(isp, data)
    zid = uuid.UUID(str(created["id"]))
    if payload.parent_id is not None:
        await _set_parent(db, isp, zid, payload.parent_id)
    view = await _node_view(db, isp, zid)
    await db.commit()
    return ok(request, view, "Zone created")


@zones_router.put(
    "/zones/{zone_id}/parent", dependencies=_ON + isp_guards(ISP_ZONES_MANAGE)
)
async def move_zone(
    request: Request,
    zone_id: uuid.UUID,
    payload: ZoneParentRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    await _set_parent(db, isp, zone_id, payload.parent_id)
    view = await _node_view(db, isp, zone_id)
    await db.commit()
    return ok(request, view, "Zone moved")


@zones_router.delete(
    "/zones/{zone_id}/tree", dependencies=_ON + isp_guards(ISP_ZONES_MANAGE)
)
async def delete_tree_zone(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspBillingService = Depends(get_billing),
) -> dict:
    from .zones_models import IspZoneNode

    await lock_tree(db, isp.isp_org_id)
    parents = parent_map(await zone_rows(db, isp.isp_org_id))
    if zone_id not in parents:
        raise IspZoneNotFoundError()
    if any(p == zone_id for p in parents.values()):
        raise IspZoneHasChildrenError()
    customers, subscribers = await _all_member_counts(db, isp, zone_id)
    if customers or subscribers:
        raise IspZoneInUseError(customers=customers, subscribers=subscribers)
    await svc.delete_zone(isp, zone_id)  # also refuses a zone on any invoice
    for node in (
        await db.execute(
            select(IspZoneNode).where(
                IspZoneNode.zone_id == zone_id, IspZoneNode.is_deleted.is_(False)
            )
        )
    ).scalars():
        node.mark_deleted()
    await db.flush()
    await db.commit()
    return ok(request, {"id": str(zone_id), "deleted": True}, "Zone deleted")


@zones_router.get(
    "/zones/{zone_id}/subtree", dependencies=_ON + isp_guards(ISP_ZONES_READ)
)
async def get_zone_subtree(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    rows = await zone_rows(db, isp.isp_org_id)
    parents = parent_map(rows)
    if zone_id not in parents:
        raise IspZoneNotFoundError()
    names = {z.id: z.name for z, _ in rows}
    return ok(
        request,
        {
            "zone_id": str(zone_id),
            "name": names[zone_id],
            "path_names": [names[p] for p in ancestry(parents, zone_id)],
            "zone_ids": sorted(str(z) for z in descendants(parents, zone_id)),
        },
        "Zone subtree",
    )


@zones_router.get("/zones/totals", dependencies=_ON + isp_guards(ISP_ZONES_READ))
async def get_zone_totals(
    request: Request,
    date_from: date = Query(),
    date_to: date = Query(),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Direct and rolled-up totals per zone. Revenue is JAZE-4's
    ``zone_revenue`` (J10); the balance is the J10 ledger (null while
    ``ISP_ZONE_LEDGER_ENABLED`` is off)."""
    from .exceptions import IspBadRequestError
    from .finance_config import get_finance_settings
    from .finance_service import IspFinanceService

    if date_to < date_from or (date_to - date_from).days > 400:
        raise IspBadRequestError("Range must be 0-400 days")
    fin = IspFinanceService(session=db)
    revenue = {
        r["zone_id"]: r
        for r in await fin.zone_revenue(isp, date_from=date_from, date_to=date_to)
    }
    ledger_on = get_finance_settings().zone_ledger_enabled
    balances: dict[str, int] = {}
    if ledger_on:
        balances = {
            z["zone_id"]: z["balance_paise"] for z in await fin.list_zone_ledgers(isp)
        }
    rows = await zone_rows(db, isp.isp_org_id)
    parents = parent_map(rows)
    _cust, subs, _inv = await _counts(db, isp)
    inv = {uuid.UUID(k): int(v.get("invoiced_paise") or 0) for k, v in revenue.items()}
    col = {uuid.UUID(k): int(v.get("collected_paise") or 0) for k, v in revenue.items()}
    bal = {uuid.UUID(k): int(v or 0) for k, v in balances.items()}
    items = []
    for node in await tree_payload(db, isp):
        zid = uuid.UUID(node["id"])
        items.append(
            {
                "zone_id": node["id"],
                "name": node["name"],
                "parent_id": node["parent_id"],
                "depth": node["depth"],
                "invoiced_paise": inv.get(zid, 0),
                "collected_paise": col.get(zid, 0),
                "balance_paise": bal.get(zid, 0) if ledger_on else None,
                "subtree_invoiced_paise": _subtree_sum(parents, inv, zid),
                "subtree_collected_paise": _subtree_sum(parents, col, zid),
                "subtree_balance_paise": _subtree_sum(parents, bal, zid)
                if ledger_on
                else None,
                "subscribers": subs.get(zid, 0),
                "subtree_subscribers": _subtree_sum(parents, subs, zid),
            }
        )
    return ok(request, {"ledger_enabled": ledger_on, "items": items}, "Zone totals")


__all__ = ["tree_payload", "zones_router"]

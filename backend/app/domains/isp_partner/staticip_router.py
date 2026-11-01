"""STATICIP-2 (ADDENDUM_06): static IP lease ledger + one-step release.

Flag ``ISP_STATICIP2_ENABLED`` (default OFF -> 404). Existing keys only:
``isp_billing.read`` (ledger, invoices), ``isp_billing.export`` (CSV),
``isp_billing.manage`` (release, same key as ending a lease).

* ``GET /static-ips/ledger`` -- JAZE-4 leases with subscriber, zone, monthly
  charge, invoices issued so far; filters status / customer / subscriber /
  zone / search (IP, subscriber id, name); server-paged.
* ``GET /static-ips/ledger/export.csv`` -- the same filters, every row.
* ``GET /static-ips/leases/{lease_id}/invoices`` -- the lease's invoices
  (``source_key`` ``sip:<lease>:<period start>``, set by ``bill_leases``).
* ``POST /static-ips/leases/{lease_id}/release`` -- ends the lease (no
  further monthly lines: ``bill_leases`` stops at ``active_until``) AND
  removes the subscriber's live JAZE-2 IP binding for that address (same
  steps as ``DELETE /subscribers/{id}/ip-bindings/{id}``), so the address
  is back in the pool's "next free". Idempotent.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from functools import lru_cache
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.queue_management.dependencies import get_queue_management_service

from .apps_export import csv_response, render_csv
from .billing_models import IspInvoice
from .billing_service import balance_of
from .constants import (
    DEFAULT_PAGE_SIZE,
    ISP_BILLING_EXPORT,
    ISP_BILLING_MANAGE,
    ISP_BILLING_READ,
    MAX_PAGE_SIZE,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .enforcement_models import IspSubscriberIpBinding
from .finance_models import IspStaticIpLease
from .finance_router import get_finance_service
from .finance_service import IspFinanceService
from .http import ok
from .models import IspCustomerProfile
from .plans_models import IspSubscriber
from .views import page as make_page

__all__ = ["staticip_router"]


class IspStaticIp2Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_STATICIP2_",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(default=False, description="ISP_STATICIP2_ENABLED")


@lru_cache(maxsize=1)
def get_staticip2_settings() -> IspStaticIp2Settings:
    return IspStaticIp2Settings()


async def RequireStaticIp2Enabled() -> None:
    if not get_staticip2_settings().enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


staticip_router = APIRouter(
    prefix="/static-ips",
    tags=["ISP Partner: static IP ledger"],
    dependencies=[Depends(RequireStaticIp2Enabled)],
)


def lease_key_prefix(lease_id: uuid.UUID) -> str:
    return f"sip:{lease_id}:"


async def _rows(
    db: AsyncSession,
    isp: IspContext,
    *,
    status_: str | None,
    isp_customer_id: uuid.UUID | None,
    subscriber_id: uuid.UUID | None,
    zone_id: uuid.UUID | None,
    search: str | None,
) -> list[tuple[Any, Any, uuid.UUID | None]]:
    """(lease, subscriber or None, zone id) inside the caller's scope."""
    children = await isp.child_ids()
    if not children:
        return []
    if isp_customer_id is not None:
        if isp_customer_id not in children:
            return []
        children = [isp_customer_id]
    q = (
        select(IspStaticIpLease, IspSubscriber, IspCustomerProfile.zone_id)
        .outerjoin(IspSubscriber, IspSubscriber.id == IspStaticIpLease.subscriber_id)
        .outerjoin(
            IspCustomerProfile,
            IspCustomerProfile.customer_organization_id
            == IspStaticIpLease.customer_organization_id,
        )
        .where(
            IspStaticIpLease.isp_organization_id == isp.isp_org_id,
            IspStaticIpLease.is_deleted.is_(False),
            IspStaticIpLease.customer_organization_id.in_(children),
        )
    )
    if status_:
        q = q.where(IspStaticIpLease.status == status_)
    if subscriber_id is not None:
        q = q.where(IspStaticIpLease.subscriber_id == subscriber_id)
    if search:
        like = f"%{search.strip()}%"
        q = q.where(
            or_(
                IspStaticIpLease.ip_address.ilike(like),
                IspSubscriber.identifier.ilike(like),
                IspSubscriber.first_name.ilike(like),
                IspSubscriber.last_name.ilike(like),
            )
        )
    out = []
    for lease, sub, cust_zone in (
        await db.execute(q.order_by(IspStaticIpLease.ip_address))
    ).all():
        zone = sub.zone_id if sub is not None and sub.zone_id else cust_zone
        if zone_id is not None and zone != zone_id:
            continue
        out.append((lease, sub, zone))
    return out


async def _invoice_stats(
    db: AsyncSession, isp: IspContext, lease_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict]:
    stats: dict[uuid.UUID, dict] = {
        i: {"invoices": 0, "billed_paise": 0, "due_paise": 0} for i in lease_ids
    }
    if not lease_ids:
        return stats
    prefixes = {lease_key_prefix(i): i for i in lease_ids}
    rows = (
        (
            await db.execute(
                select(IspInvoice).where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.doc_type == "invoice",
                    or_(*(IspInvoice.source_key.like(p + "%") for p in prefixes)),
                )
            )
        )
        .scalars()
        .all()
    )
    for inv in rows:
        lease_id = prefixes.get(":".join((inv.source_key or "").split(":")[:2]) + ":")
        if lease_id is None:
            continue
        s = stats[lease_id]
        s["invoices"] += 1
        s["billed_paise"] += inv.total_paise
        s["due_paise"] += balance_of(inv)
    return stats


async def _zone_names(db: AsyncSession, ids: set) -> dict:
    from .billing_models import IspZone

    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = await db.execute(select(IspZone.id, IspZone.name).where(IspZone.id.in_(ids)))
    return dict(rows.all())


async def _views(
    db: AsyncSession, isp: IspContext, svc: IspFinanceService, rows: list
) -> list[dict]:
    names = await svc._names([r[0] for r in rows])
    stats = await _invoice_stats(db, isp, [r[0].id for r in rows])
    zones = await _zone_names(db, {r[2] for r in rows})
    out = []
    for lease, sub, zone in rows:
        v = svc.lease_view(
            lease,
            sub_name=names["subs"].get(lease.subscriber_id),
            customer_name=names["orgs"].get(lease.customer_organization_id),
        )
        v["subscriber_identifier"] = sub.identifier if sub is not None else None
        v["zone_id"] = str(zone) if zone else None
        v["zone_name"] = zones.get(zone)
        v.update(stats[lease.id])
        out.append(v)
    return out


_Status = Query(default=None, pattern="^(active|ended)$")


@staticip_router.get("/ledger", dependencies=isp_guards(ISP_BILLING_READ))
async def static_ip_ledger(
    request: Request,
    status: str | None = _Status,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    zone_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:
    rows = await _rows(
        db,
        isp,
        status_=status,
        isp_customer_id=isp_customer_id,
        subscriber_id=subscriber_id,
        zone_id=zone_id,
        search=search,
    )
    total = len(rows)
    chunk = rows[(page - 1) * page_size : page * page_size]
    items = await _views(db, isp, svc, chunk)
    active = [r[0] for r in rows if r[0].status == "active"]
    summary = {
        "active": len(active),
        "ended": total - len(active),
        "monthly_paise": sum(lease.monthly_amount_paise for lease in active),
    }
    return ok(
        request,
        {**make_page(items, total, page, page_size), "summary": summary},
        "Static IP ledger",
    )


_COLUMNS = (
    ("IP", lambda r: r["ip_address"]),
    ("Status", lambda r: r["status"]),
    ("Subscriber ID", lambda r: r["subscriber_identifier"]),
    ("Subscriber", lambda r: r["subscriber_name"]),
    ("Customer", lambda r: r["customer_name"]),
    ("Zone", lambda r: r["zone_name"]),
    ("Since", lambda r: r["active_since"]),
    ("Until", lambda r: r["active_until"]),
    ("Monthly (Rs)", lambda r: r["monthly_amount_paise"] / 100),
    ("GST included", lambda r: "yes" if r["price_includes_gst"] else "no"),
    ("Billed through", lambda r: r["billed_through"]),
    ("Invoices", lambda r: r["invoices"]),
    ("Billed (Rs)", lambda r: r["billed_paise"] / 100),
    ("Due (Rs)", lambda r: r["due_paise"] / 100),
)


@staticip_router.get("/ledger/export.csv", dependencies=isp_guards(ISP_BILLING_EXPORT))
async def static_ip_ledger_export(
    status: str | None = _Status,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    zone_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspFinanceService = Depends(get_finance_service),
) -> Response:
    rows = await _rows(
        db,
        isp,
        status_=status,
        isp_customer_id=isp_customer_id,
        subscriber_id=subscriber_id,
        zone_id=zone_id,
        search=search,
    )
    items = await _views(db, isp, svc, rows)
    return csv_response(render_csv(_COLUMNS, items), "static-ip-leases.csv")


@staticip_router.get(
    "/leases/{lease_id}/invoices", dependencies=isp_guards(ISP_BILLING_READ)
)
async def static_ip_lease_invoices(
    request: Request,
    lease_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:
    lease = await svc._lease(isp, lease_id)  # scope + 404
    rows = (
        (
            await db.execute(
                select(IspInvoice)
                .where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.source_key.like(lease_key_prefix(lease.id) + "%"),
                )
                .order_by(IspInvoice.period_start)
            )
        )
        .scalars()
        .all()
    )
    items = [
        {
            "id": str(i.id),
            "number": i.number,
            "doc_type": i.doc_type,
            "period_start": i.period_start.isoformat() if i.period_start else None,
            "period_end": i.period_end.isoformat() if i.period_end else None,
            "total_paise": i.total_paise,
            "balance_paise": balance_of(i) if i.doc_type == "invoice" else 0,
            "status": i.status,
        }
        for i in rows
    ]
    return ok(request, {"items": items, "total": len(items)}, "Lease invoices")


class IspStaticIpReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    until: date | None = None
    release_binding: bool = True
    reason: Literal["moved", "disconnected", "downgraded", "other"] | None = None


@staticip_router.post(
    "/leases/{lease_id}/release", dependencies=isp_guards(ISP_BILLING_MANAGE)
)
async def release_static_ip(
    request: Request,
    lease_id: uuid.UUID,
    payload: IspStaticIpReleaseRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    svc: IspFinanceService = Depends(get_finance_service),
    queue_service=Depends(get_queue_management_service),  # noqa: B008
) -> dict:
    lease = await svc._lease(isp, lease_id)  # scope + 404
    view = await svc.end_lease(isp, lease.id, until=payload.until)
    released: list[str] = []
    warnings: list[str] = []
    if payload.release_binding and lease.subscriber_id is not None:
        bindings = (
            (
                await db.execute(
                    select(IspSubscriberIpBinding).where(
                        IspSubscriberIpBinding.isp_organization_id == isp.isp_org_id,
                        IspSubscriberIpBinding.subscriber_id == lease.subscriber_id,
                        IspSubscriberIpBinding.ip == lease.ip_address,
                        IspSubscriberIpBinding.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        for b in bindings:
            if b.queue_assignment_id is not None:
                try:
                    await queue_service.remove_queue(
                        b.queue_assignment_id,
                        actor_user_id=isp.user_id,
                        requesting_organization_id=b.customer_organization_id,
                    )
                except Exception as exc:  # noqa: BLE001 -- lease + IP still freed
                    warnings.append(f"router queue not removed: {str(exc)[:150]}")
            b.is_deleted, b.deleted_at = True, datetime.now(UTC)
            released.append(str(b.id))
        await db.flush()
    still_bound = (
        await db.execute(
            select(func.count())
            .select_from(IspSubscriberIpBinding)
            .where(
                IspSubscriberIpBinding.isp_organization_id == isp.isp_org_id,
                IspSubscriberIpBinding.ip == lease.ip_address,
                IspSubscriberIpBinding.is_deleted.is_(False),
            )
        )
    ).scalar_one()
    return ok(
        request,
        {
            "lease": view,
            "released_binding_ids": released,
            # "next free" skips live bindings: none left -> the IP is free
            "ip_back_in_pool": int(still_bound) == 0,
            "warnings": warnings,
        },
        "Static IP released",
    )

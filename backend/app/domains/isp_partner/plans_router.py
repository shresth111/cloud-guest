"""``/isp`` speed groups, packages, coupon batches, subscribers, plan
settings (ADDENDUM_02 §8). Same guard stack; keys pinned ORGANIZATION.
Groups and packages are ISP-wide; coupons and subscribers are per customer
(confinement applies)."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.queue_management.dependencies import get_queue_management_service
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.voucher.dependencies import get_voucher_service

from .constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from .coupon_pdf import render_coupon_sheet
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .plans_service import IspPlansService, suggest_name
from .service_control import IspServiceControl
from .views import page as make_page

plans_router = APIRouter(tags=["ISP Partner: plans"])

_Page = Query(default=1, ge=1)
_PageSize = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)

PLANS_READ, PLANS_CREATE, PLANS_UPDATE, PLANS_DELETE = (
    "isp_plans.read",
    "isp_plans.create",
    "isp_plans.update",
    "isp_plans.delete",
)
COUPONS_READ, COUPONS_CREATE, COUPONS_EXPORT, COUPONS_UPDATE = (
    "isp_coupons.read",
    "isp_coupons.create",
    "isp_coupons.export",
    "isp_coupons.update",
)
SUBS_READ, SUBS_UPDATE = "isp_subscribers.read", "isp_subscribers.update"


def get_plans_service(
    db: AsyncSession = Depends(get_db_session),
    queue_service=Depends(get_queue_management_service),  # noqa: B008
    voucher_service=Depends(get_voucher_service),  # noqa: B008
    audit=Depends(get_rbac_repository),  # noqa: B008
) -> IspPlansService:
    return IspPlansService(
        session=db,
        queue_service=queue_service,
        voucher_service=voucher_service,
        audit=audit,
    )


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Burst(_Body):
    download_kbps: int | None = Field(default=None, ge=64, le=10_000_000)
    upload_kbps: int | None = Field(default=None, ge=64, le=10_000_000)
    threshold_kbps: int | None = Field(default=None, ge=64, le=10_000_000)
    time_seconds: int | None = Field(default=None, ge=1, le=3600)


class GroupRequest(_Body):
    name: str = Field(min_length=1, max_length=100)
    download_kbps: int = Field(ge=64, le=10_000_000)
    upload_kbps: int = Field(ge=64, le=10_000_000)
    burst: Burst | None = None
    priority: int | None = Field(default=None, ge=1, le=8)
    notes: str | None = None


class GroupPatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    download_kbps: int | None = Field(default=None, ge=64, le=10_000_000)
    upload_kbps: int | None = Field(default=None, ge=64, le=10_000_000)
    burst: Burst | None = None
    priority: int | None = Field(default=None, ge=1, le=8)
    notes: str | None = None


class PackageRequest(_Body):
    speed_group_id: uuid.UUID
    type: str = Field(pattern="^(prepaid|postpaid)$")
    validity_days: int | None = Field(default=None, ge=1, le=3650)
    price_paise: int = Field(default=0, ge=0)
    price_includes_gst: bool = True
    data_cap_mb: int | None = Field(default=None, ge=1)
    max_devices: int | None = Field(default=None, ge=1, le=32)
    name: str | None = Field(default=None, max_length=150)


class PackagePatch(_Body):
    speed_group_id: uuid.UUID | None = None
    type: str | None = Field(default=None, pattern="^(prepaid|postpaid)$")
    validity_days: int | None = Field(default=None, ge=1, le=3650)
    price_paise: int | None = Field(default=None, ge=0)
    price_includes_gst: bool | None = None
    data_cap_mb: int | None = Field(default=None, ge=1)
    max_devices: int | None = Field(default=None, ge=1, le=32)
    name: str | None = Field(default=None, min_length=1, max_length=150)


class DuplicateRequest(_Body):
    validity_days: int = Field(ge=1, le=3650)
    price_paise: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, max_length=150)


class LadderRequest(_Body):
    speeds_mbps: list[float] = Field(min_length=1, max_length=60)
    validities_days: list[int] = Field(min_length=1, max_length=10)
    type: str = Field(default="prepaid", pattern="^(prepaid|postpaid)$")
    upload_equals_download: bool = True
    prices_paise: dict[str, int] | None = None


class PlanSettingsRequest(_Body):
    default_validity_days: int = Field(ge=1, le=3650)


class CouponBatchRequest(_Body):
    package_id: uuid.UUID
    isp_customer_id: uuid.UUID
    isp_location_id: uuid.UUID | None = None
    quantity: int = Field(ge=1, le=5000)
    code_length: int | None = Field(default=None, ge=8, le=16)
    code_prefix: str | None = Field(default=None, max_length=6, pattern="^[A-Z0-9]*$")
    shelf_life_days: int | None = Field(default=None, ge=1, le=3650)


class SubscriberRequest(_Body):
    isp_customer_id: uuid.UUID
    identifier: str = Field(min_length=3, max_length=255)
    display_name: str | None = Field(default=None, max_length=200)
    package_id: uuid.UUID
    valid_from: datetime | None = None


class SubscriberPatch(_Body):
    package_id: uuid.UUID | None = None
    valid_until: datetime | None = None
    display_name: str | None = Field(default=None, max_length=200)


# ---------------------------------------------------------------------------
# plan settings + name suggestion
# ---------------------------------------------------------------------------


@plans_router.get("/plan-settings", dependencies=isp_guards(PLANS_READ))
async def get_plan_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(request, await svc.plan_settings(isp), "Plan settings")


@plans_router.put("/plan-settings", dependencies=isp_guards(PLANS_UPDATE))
async def put_plan_settings(
    request: Request,
    payload: PlanSettingsRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(
        request,
        await svc.put_plan_settings(isp, payload.default_validity_days),
        "Plan settings saved",
    )


@plans_router.get("/packages/suggest-name", dependencies=isp_guards(PLANS_READ))
async def suggest_package_name(
    request: Request,
    speed_group_id: uuid.UUID = Query(),
    type: str = Query(pattern="^(prepaid|postpaid)$"),
    validity_days: int = Query(ge=1, le=3650),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    g = await svc.group(isp, speed_group_id)
    return ok(
        request, {"name": suggest_name(g.name, type, validity_days)}, "Suggested name"
    )


# ---------------------------------------------------------------------------
# speed groups
# ---------------------------------------------------------------------------


@plans_router.get("/speed-groups", dependencies=isp_guards(PLANS_READ))
async def list_groups(
    request: Request,
    status: str | None = Query(default=None, pattern="^(active|disabled)$"),
    search: str | None = Query(default=None, max_length=100),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.sync_subscribers(isp)
    items, total = await svc.list_groups(
        isp, status=status, search=search, page=page, page_size=page_size
    )
    return ok(request, make_page(items, total, page, page_size), "Speed groups")


@plans_router.post(
    "/speed-groups", status_code=201, dependencies=isp_guards(PLANS_CREATE)
)
async def create_group(
    request: Request,
    payload: GroupRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    g = await svc.create_group(isp, payload.model_dump())
    return ok(request, (await svc.group_views(isp, [g]))[0], "Speed group created")


@plans_router.get("/speed-groups/{speed_group_id}", dependencies=isp_guards(PLANS_READ))
async def get_group(
    request: Request,
    speed_group_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(
        request,
        (await svc.group_views(isp, [await svc.group(isp, speed_group_id)]))[0],
        "Speed group",
    )


@plans_router.patch(
    "/speed-groups/{speed_group_id}", dependencies=isp_guards(PLANS_UPDATE)
)
async def patch_group(
    request: Request,
    speed_group_id: uuid.UUID,
    payload: GroupPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    g = await svc.update_group(
        isp, speed_group_id, payload.model_dump(exclude_unset=True)
    )
    return ok(
        request,
        (await svc.group_views(isp, [g]))[0],
        "Speed group updated (applies at next login)",
    )


@plans_router.post(
    "/speed-groups/{speed_group_id}/disable", dependencies=isp_guards(PLANS_UPDATE)
)
async def disable_group(
    request: Request,
    speed_group_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    g = await svc.set_group_status(isp, speed_group_id, "disabled")
    return ok(request, (await svc.group_views(isp, [g]))[0], "Speed group disabled")


@plans_router.post(
    "/speed-groups/{speed_group_id}/enable", dependencies=isp_guards(PLANS_UPDATE)
)
async def enable_group(
    request: Request,
    speed_group_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    g = await svc.set_group_status(isp, speed_group_id, "active")
    return ok(request, (await svc.group_views(isp, [g]))[0], "Speed group enabled")


@plans_router.delete(
    "/speed-groups/{speed_group_id}", dependencies=isp_guards(PLANS_DELETE)
)
async def delete_group(
    request: Request,
    speed_group_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.delete_group(isp, speed_group_id)
    return ok(request, {"deleted": True}, "Speed group deleted")


@plans_router.get(
    "/speed-groups/{speed_group_id}/subscribers", dependencies=isp_guards(SUBS_READ)
)
async def group_subscribers(
    request: Request,
    speed_group_id: uuid.UUID,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern="^(active|expired|disabled)$"),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.group(isp, speed_group_id)
    items, total = await svc.list_subscribers(
        isp,
        isp_customer_id=isp_customer_id,
        speed_group_id=speed_group_id,
        status=status,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Subscribers")


# ---------------------------------------------------------------------------
# packages
# ---------------------------------------------------------------------------


@plans_router.get("/packages", dependencies=isp_guards(PLANS_READ))
async def list_packages(
    request: Request,
    speed_group_id: uuid.UUID | None = Query(default=None),
    type: str | None = Query(default=None, pattern="^(prepaid|postpaid)$"),
    status: str | None = Query(default=None, pattern="^(active|disabled)$"),
    search: str | None = Query(default=None, max_length=150),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.sync_subscribers(isp)
    items, total = await svc.list_packages(
        isp,
        speed_group_id=speed_group_id,
        type_=type,
        status=status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Packages")


@plans_router.post("/packages", status_code=201, dependencies=isp_guards(PLANS_CREATE))
async def create_package(
    request: Request,
    payload: PackageRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    p = await svc.create_package(isp, payload.model_dump())
    return ok(request, (await svc.package_views(isp, [p]))[0], "Package created")


@plans_router.post(
    "/packages/ladder", status_code=201, dependencies=isp_guards(PLANS_CREATE)
)
async def ladder(
    request: Request,
    payload: LadderRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    data = payload.model_dump()
    data["speeds_mbps"] = [
        int(s) if float(s).is_integer() else s for s in data["speeds_mbps"]
    ]
    return ok(request, await svc.ladder(isp, data), "Ladder created")


@plans_router.get("/packages/{package_id}", dependencies=isp_guards(PLANS_READ))
async def get_package(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(
        request,
        (await svc.package_views(isp, [await svc.package(isp, package_id)]))[0],
        "Package",
    )


@plans_router.patch("/packages/{package_id}", dependencies=isp_guards(PLANS_UPDATE))
async def patch_package(
    request: Request,
    package_id: uuid.UUID,
    payload: PackagePatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    p = await svc.update_package(
        isp, package_id, payload.model_dump(exclude_unset=True)
    )
    return ok(request, (await svc.package_views(isp, [p]))[0], "Package updated")


@plans_router.post(
    "/packages/{package_id}/duplicate",
    status_code=201,
    dependencies=isp_guards(PLANS_CREATE),
)
async def duplicate_package(
    request: Request,
    package_id: uuid.UUID,
    payload: DuplicateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    p = await svc.duplicate_package(isp, package_id, payload.model_dump())
    return ok(request, (await svc.package_views(isp, [p]))[0], "Package duplicated")


@plans_router.post(
    "/packages/{package_id}/disable", dependencies=isp_guards(PLANS_UPDATE)
)
async def disable_package(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    p = await svc.set_package_status(isp, package_id, "disabled")
    return ok(request, (await svc.package_views(isp, [p]))[0], "Package disabled")


@plans_router.post(
    "/packages/{package_id}/enable", dependencies=isp_guards(PLANS_UPDATE)
)
async def enable_package(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    p = await svc.set_package_status(isp, package_id, "active")
    return ok(request, (await svc.package_views(isp, [p]))[0], "Package enabled")


@plans_router.delete("/packages/{package_id}", dependencies=isp_guards(PLANS_DELETE))
async def delete_package(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.delete_package(isp, package_id)
    return ok(request, {"deleted": True}, "Package deleted")


# ---------------------------------------------------------------------------
# coupons
# ---------------------------------------------------------------------------


@plans_router.post(
    "/coupon-batches", status_code=201, dependencies=isp_guards(COUPONS_CREATE)
)
async def create_coupon_batch(
    request: Request,
    payload: CouponBatchRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    control = IspServiceControl(session=db)
    batch, warnings = await svc.create_coupon_batch(
        isp, payload.model_dump(), is_cut=control.is_cut
    )
    data = (await svc.batch_views(isp, [batch]))[0]
    data["coupon_login_disabled_at_locations"] = warnings
    return ok(request, data, "Coupons generated")


@plans_router.get("/coupon-batches", dependencies=isp_guards(COUPONS_READ))
async def list_coupon_batches(
    request: Request,
    package_id: uuid.UUID | None = Query(default=None),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern="^(active|revoked|expired)$"),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    items, total = await svc.list_batches(
        isp,
        package_id=package_id,
        isp_customer_id=isp_customer_id,
        status=status,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Coupon batches")


@plans_router.get(
    "/coupon-batches/{coupon_batch_id}", dependencies=isp_guards(COUPONS_READ)
)
async def get_coupon_batch(
    request: Request,
    coupon_batch_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(
        request,
        (await svc.batch_views(isp, [await svc.coupon_batch(isp, coupon_batch_id)]))[0],
        "Coupon batch",
    )


@plans_router.get(
    "/coupon-batches/{coupon_batch_id}/coupons", dependencies=isp_guards(COUPONS_READ)
)
async def list_coupons(
    request: Request,
    coupon_batch_id: uuid.UUID,
    status: str | None = Query(
        default=None, pattern="^(unused|active|used_up|expired|revoked)$"
    ),
    search: str | None = Query(default=None, max_length=64),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    items, total = await svc.list_coupons(
        isp,
        coupon_batch_id,
        status=status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Coupons")


async def _batch_meta(isp: IspContext, svc: IspPlansService, batch: Any) -> dict:
    from .plans_models import IspPackage, IspSpeedGroup

    pkg = await svc.session.get(IspPackage, batch.package_id)
    grp = await svc.session.get(IspSpeedGroup, pkg.speed_group_id) if pkg else None
    return {
        "isp_name": isp.organization.name,
        "package_name": pkg.name if pkg else "",
        "speed": f"{grp.download_kbps // 1024} Mbps" if grp else "",
        "speed_kbps": grp.download_kbps if grp else None,
        "validity_days": pkg.validity_days if pkg else None,
        "valid_until": batch.shelf_life_until.date().isoformat()
        if batch.shelf_life_until
        else None,
        "portal_url": None,
    }


@plans_router.get(
    "/coupon-batches/{coupon_batch_id}/export.csv",
    dependencies=isp_guards(COUPONS_EXPORT),
)
async def export_coupons(
    coupon_batch_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> Response:
    batch = await svc.coupon_batch(isp, coupon_batch_id)
    meta = await _batch_meta(isp, svc, batch)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "serial",
            "code",
            "package",
            "speed",
            "validity_days",
            "status",
            "expires_at",
            "redeemed_by_masked",
        ]
    )
    for serial, v in await svc._all_coupons(batch):
        view = svc.coupon_view(serial, v)
        w.writerow(
            [
                serial,
                v.code,
                meta["package_name"],
                meta["speed"],
                meta["validity_days"],
                view["status"],
                view["expires_at"] or "",
                view["redeemed_by"] or "",
            ]
        )
    await svc.sync_subscribers(isp)
    name = f"coupons-{batch.serial_prefix}-{batch.batch_seq:04d}.csv"
    return Response(
        content=buf.getvalue().encode(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


@plans_router.get(
    "/coupon-batches/{coupon_batch_id}/print.pdf",
    dependencies=isp_guards(COUPONS_EXPORT),
)
async def print_coupons(
    coupon_batch_id: uuid.UUID,
    layout: str = Query(default="a4-24", pattern="^(a4-24|a4-40|thermal-58mm)$"),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> Response:
    batch = await svc.coupon_batch(isp, coupon_batch_id)
    meta = await _batch_meta(isp, svc, batch)
    coupons = [
        svc.coupon_view(s, v)
        for s, v in await svc._all_coupons(batch)
        if v.status == "unused"
    ]
    content = render_coupon_sheet(coupons, meta, layout=layout)
    name = f"coupons-{batch.serial_prefix}-{batch.batch_seq:04d}-{layout}.pdf"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


@plans_router.post(
    "/coupon-batches/{coupon_batch_id}/revoke", dependencies=isp_guards(COUPONS_UPDATE)
)
async def revoke_coupon_batch(
    request: Request,
    coupon_batch_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(
        request, await svc.revoke_batch(isp, coupon_batch_id), "Unused coupons revoked"
    )


@plans_router.post(
    "/coupons/{coupon_id}/revoke", dependencies=isp_guards(COUPONS_UPDATE)
)
async def revoke_coupon(
    request: Request,
    coupon_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(request, await svc.revoke_coupon(isp, coupon_id), "Coupon revoked")


# ---------------------------------------------------------------------------
# subscribers
# ---------------------------------------------------------------------------


@plans_router.get("/subscribers", dependencies=isp_guards(SUBS_READ))
async def list_subscribers(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    speed_group_id: uuid.UUID | None = Query(default=None),
    package_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern="^(active|expired|disabled)$"),
    search: str | None = Query(default=None, max_length=100),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    items, total = await svc.list_subscribers(
        isp,
        isp_customer_id=isp_customer_id,
        speed_group_id=speed_group_id,
        package_id=package_id,
        status=status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Subscribers")


@plans_router.post(
    "/subscribers", status_code=201, dependencies=isp_guards(SUBS_UPDATE)
)
async def create_subscriber(
    request: Request,
    payload: SubscriberRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    s = await svc.create_subscriber(isp, payload.model_dump())
    return ok(request, await svc.subscriber_detail(isp, s.id), "Subscriber created")


@plans_router.get("/subscribers/{subscriber_id}", dependencies=isp_guards(SUBS_READ))
async def get_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    return ok(request, await svc.subscriber_detail(isp, subscriber_id), "Subscriber")


@plans_router.patch(
    "/subscribers/{subscriber_id}", dependencies=isp_guards(SUBS_UPDATE)
)
async def patch_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: SubscriberPatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.update_subscriber(
        isp, subscriber_id, payload.model_dump(exclude_unset=True)
    )
    return ok(
        request, await svc.subscriber_detail(isp, subscriber_id), "Subscriber updated"
    )


@plans_router.post(
    "/subscribers/{subscriber_id}/disable", dependencies=isp_guards(SUBS_UPDATE)
)
async def disable_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.set_subscriber_status(isp, subscriber_id, False)
    return ok(
        request, await svc.subscriber_detail(isp, subscriber_id), "Subscriber disabled"
    )


@plans_router.post(
    "/subscribers/{subscriber_id}/enable", dependencies=isp_guards(SUBS_UPDATE)
)
async def enable_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPlansService = Depends(get_plans_service),
) -> dict:
    await svc.set_subscriber_status(isp, subscriber_id, True)
    return ok(
        request, await svc.subscriber_detail(isp, subscriber_id), "Subscriber enabled"
    )

"""Phase 2a: speed groups, packages, coupons, subscribers (ADDENDUM_02).

Coupons are existing ``Voucher`` rows made by ``VoucherService`` inside the
ISP customer's own org (``requesting_organization_id=<customer>``); speed is
an existing ``QueueProfile`` per (group, customer) made by
``QueueManagementService``. Nothing is ever created in a non-ISP org: every
customer id goes through ``IspScope`` first.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select, update

from app.common.masking import mask_identifier

from .billing_service import IspBillingService
from .dependencies import IspContext
from .exceptions import _err
from .plans_models import (
    IspCouponBatch,
    IspCouponBatchPart,
    IspPackage,
    IspPackageMaterialization,
    IspPlanSettings,
    IspSpeedGroup,
    IspSubscriber,
)
from .scoping import IspScope

IspGroupInUseError = _err(
    "IspGroupInUseError",
    "ISP_GROUP_IN_USE",
    409,
    "This speed group still has packages or subscribers",
)
IspPackageInUseError = _err(
    "IspPackageInUseError",
    "ISP_PACKAGE_IN_USE",
    409,
    "This package is in use; disable it or duplicate it instead",
)
IspPackageDisabledError = _err(
    "IspPackageDisabledError", "ISP_PACKAGE_DISABLED", 409, "This package is disabled"
)
IspPackageNeedsPriceError = _err(
    "IspPackageNeedsPriceError",
    "ISP_PACKAGE_NEEDS_PRICE",
    409,
    "Set a price for this package first",
)
IspBurstIncompleteError = _err(
    "IspBurstIncompleteError",
    "ISP_BURST_INCOMPLETE",
    422,
    "Burst needs all four values, above the base rate",
)
IspSpeedGroupNotFoundError = _err(
    "IspSpeedGroupNotFoundError",
    "ISP_SPEED_GROUP_NOT_FOUND",
    404,
    "Speed group not found",
)
IspPackageNotFoundError = _err(
    "IspPackageNotFoundError", "ISP_PACKAGE_NOT_FOUND", 404, "Package not found"
)
IspCouponBatchNotFoundError = _err(
    "IspCouponBatchNotFoundError",
    "ISP_COUPON_BATCH_NOT_FOUND",
    404,
    "Coupon batch not found",
)
IspCouponNotFoundError = _err(
    "IspCouponNotFoundError", "ISP_COUPON_NOT_FOUND", 404, "Coupon not found"
)
IspSubscriberNotFoundError = _err(
    "IspSubscriberNotFoundError",
    "ISP_SUBSCRIBER_NOT_FOUND",
    404,
    "Subscriber not found",
)
IspNameTakenError = _err(
    "IspNameTakenError", "ISP_NAME_TAKEN", 409, "That name is already used"
)

#: ADDENDUM_02 §2 coupon status vocabulary from voucher status.
COUPON_STATUS = {
    "unused": "unused",
    "active": "active",
    "exhausted": "used_up",
    "expired": "expired",
    "revoked": "revoked",
}
VOUCHER_BATCH_MAX = 1000
KBPS_PER_MBPS = 1024
SYNC_MIN_INTERVAL = timedelta(seconds=60)
_last_sync: dict[uuid.UUID, datetime] = {}


def suggest_name(group_name: str, type_: str, validity_days: int) -> str:
    return f"{group_name} · {type_.title()} · {validity_days} days"


def _iso(v: Any) -> Any:
    return v.isoformat() if hasattr(v, "isoformat") else v


class IspPlansService:
    def __init__(
        self,
        *,
        session: Any,
        queue_service: Any = None,
        voucher_service: Any = None,
        audit: Any = None,
        clock: Any = None,
    ) -> None:
        self.session = session
        self.queue_service = queue_service
        self.voucher_service = voucher_service
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # lookups
    # ------------------------------------------------------------------
    async def group(self, isp: IspContext, group_id: uuid.UUID) -> IspSpeedGroup:
        g = await self.session.get(IspSpeedGroup, group_id)
        if g is None or g.is_deleted or g.isp_organization_id != isp.isp_org_id:
            raise IspSpeedGroupNotFoundError()
        return g

    async def package(self, isp: IspContext, package_id: uuid.UUID) -> IspPackage:
        p = await self.session.get(IspPackage, package_id)
        if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
            raise IspPackageNotFoundError()
        return p

    async def coupon_batch(
        self, isp: IspContext, batch_id: uuid.UUID
    ) -> IspCouponBatch:
        b = await self.session.get(IspCouponBatch, batch_id)
        if b is None or b.is_deleted or b.isp_organization_id != isp.isp_org_id:
            raise IspCouponBatchNotFoundError()
        try:
            await IspScope.assert_customer(isp, b.customer_organization_id)
        except Exception:  # noqa: BLE001 -- out of confinement: same 404
            raise IspCouponBatchNotFoundError() from None
        return b

    async def subscriber(
        self, isp: IspContext, subscriber_id: uuid.UUID
    ) -> IspSubscriber:
        s = await self.session.get(IspSubscriber, subscriber_id)
        if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
            raise IspSubscriberNotFoundError()
        try:
            await IspScope.assert_customer(isp, s.customer_organization_id)
        except Exception:  # noqa: BLE001
            raise IspSubscriberNotFoundError() from None
        return s

    async def _name_taken(
        self, model: Any, isp: IspContext, name: str, *, except_id=None
    ) -> bool:
        q = select(model.id).where(
            model.isp_organization_id == isp.isp_org_id,
            func.lower(model.name) == name.strip().lower(),
            model.deleted_at.is_(None),
        )
        if except_id is not None:
            q = q.where(model.id != except_id)
        return (await self.session.execute(q.limit(1))).first() is not None

    # ------------------------------------------------------------------
    # plan settings
    # ------------------------------------------------------------------
    async def plan_settings(self, isp: IspContext) -> dict:
        row = (
            await self.session.execute(
                select(IspPlanSettings).where(
                    IspPlanSettings.isp_organization_id == isp.isp_org_id
                )
            )
        ).scalar_one_or_none()
        return {"default_validity_days": row.default_validity_days if row else 30}

    async def put_plan_settings(
        self, isp: IspContext, default_validity_days: int
    ) -> dict:
        row = (
            await self.session.execute(
                select(IspPlanSettings).where(
                    IspPlanSettings.isp_organization_id == isp.isp_org_id
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = IspPlanSettings(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id
            )
            self.session.add(row)
        row.default_validity_days = default_validity_days
        await self.session.flush()
        return {"default_validity_days": row.default_validity_days}

    # ------------------------------------------------------------------
    # speed groups
    # ------------------------------------------------------------------
    @staticmethod
    def _check_burst(data: dict, download: int, upload: int) -> None:
        burst = data.get("burst") or {}
        values = [
            burst.get(k)
            for k in ("download_kbps", "upload_kbps", "threshold_kbps", "time_seconds")
        ]
        if any(v is not None for v in values):
            if any(v is None for v in values):
                raise IspBurstIncompleteError()
            if values[0] <= download or values[1] <= upload:
                raise IspBurstIncompleteError("Burst rate must be above the base rate")

    async def _group_counts(self, group_ids: list[uuid.UUID]) -> tuple[dict, dict]:
        from app.domains.guest.models import GuestSession
        from app.domains.voucher.models import Voucher

        total = {}
        active = {}
        if not group_ids:
            return total, active
        rows = await self.session.execute(
            select(IspSubscriber.speed_group_id, func.count())
            .where(
                IspSubscriber.speed_group_id.in_(group_ids),
                IspSubscriber.status == "active",
                IspSubscriber.is_deleted.is_(False),
            )
            .group_by(IspSubscriber.speed_group_id)
        )
        total = dict(rows.all())
        rows = await self.session.execute(
            select(
                IspPackage.speed_group_id, func.count(func.distinct(GuestSession.id))
            )
            .join(IspCouponBatch, IspCouponBatch.package_id == IspPackage.id)
            .join(
                IspCouponBatchPart,
                IspCouponBatchPart.coupon_batch_id == IspCouponBatch.id,
            )
            .join(Voucher, Voucher.batch_id == IspCouponBatchPart.voucher_batch_id)
            .join(GuestSession, GuestSession.voucher_id == Voucher.id)
            .where(
                IspPackage.speed_group_id.in_(group_ids),
                GuestSession.status == "active",
                GuestSession.organization_id == IspCouponBatch.customer_organization_id,
            )
            .group_by(IspPackage.speed_group_id)
        )
        active = dict(rows.all())
        return total, active

    async def group_views(
        self, isp: IspContext, groups: list[IspSpeedGroup]
    ) -> list[dict]:
        ids = [g.id for g in groups]
        packages = []
        if ids:
            packages = (
                (
                    await self.session.execute(
                        select(IspPackage)
                        .where(
                            IspPackage.speed_group_id.in_(ids),
                            IspPackage.is_deleted.is_(False),
                        )
                        .order_by(IspPackage.validity_days)
                    )
                )
                .scalars()
                .all()
            )
        total, active = await self._group_counts(ids)
        out = []
        for g in groups:
            pk = [p for p in packages if p.speed_group_id == g.id]
            out.append(
                {
                    "id": str(g.id),
                    "name": g.name,
                    "download_kbps": g.download_kbps,
                    "upload_kbps": g.upload_kbps,
                    "burst": {
                        "download_kbps": g.burst_download_kbps,
                        "upload_kbps": g.burst_upload_kbps,
                        "threshold_kbps": g.burst_threshold_kbps,
                        "time_seconds": g.burst_time_seconds,
                    },
                    "priority": g.priority,
                    "status": g.status,
                    "notes": g.notes,
                    "packages": [
                        {
                            "id": str(p.id),
                            "name": p.name,
                            "validity_days": p.validity_days,
                            "status": p.status,
                        }
                        for p in pk
                    ],
                    "active_users": int(active.get(g.id, 0)),
                    "total_users": int(total.get(g.id, 0)),
                    "can_delete": not pk and not total.get(g.id),
                    "created_at": _iso(g.created_at),
                }
            )
        return out

    async def list_groups(
        self, isp: IspContext, *, status=None, search=None, page=1, page_size=25
    ) -> tuple[list[dict], int]:
        cond = [
            IspSpeedGroup.isp_organization_id == isp.isp_org_id,
            IspSpeedGroup.is_deleted.is_(False),
        ]
        if status:
            cond.append(IspSpeedGroup.status == status)
        if search:
            cond.append(IspSpeedGroup.name.ilike(f"%{search.strip()}%"))
        total = (
            await self.session.execute(
                select(func.count()).select_from(IspSpeedGroup).where(*cond)
            )
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    select(IspSpeedGroup)
                    .where(*cond)
                    .order_by(IspSpeedGroup.download_kbps, IspSpeedGroup.name)
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.group_views(isp, list(rows)), int(total)

    async def create_group(self, isp: IspContext, data: dict) -> IspSpeedGroup:
        if await self._name_taken(IspSpeedGroup, isp, data["name"]):
            raise IspNameTakenError()
        self._check_burst(data, data["download_kbps"], data["upload_kbps"])
        burst = data.get("burst") or {}
        g = IspSpeedGroup(
            isp_organization_id=isp.isp_org_id,
            name=data["name"].strip(),
            download_kbps=data["download_kbps"],
            upload_kbps=data["upload_kbps"],
            burst_download_kbps=burst.get("download_kbps"),
            burst_upload_kbps=burst.get("upload_kbps"),
            burst_threshold_kbps=burst.get("threshold_kbps"),
            burst_time_seconds=burst.get("time_seconds"),
            priority=data.get("priority") or 8,
            notes=data.get("notes"),
            status="active",
            created_by=isp.user_id,
        )
        self.session.add(g)
        await self.session.flush()
        return g

    async def update_group(
        self, isp: IspContext, group_id: uuid.UUID, data: dict
    ) -> IspSpeedGroup:
        g = await self.group(isp, group_id)
        if data.get("name") and await self._name_taken(
            IspSpeedGroup, isp, data["name"], except_id=g.id
        ):
            raise IspNameTakenError()
        down = data.get("download_kbps", g.download_kbps)
        up = data.get("upload_kbps", g.upload_kbps)
        if "burst" in data:
            self._check_burst(data, down, up)
            burst = data["burst"] or {}
            g.burst_download_kbps = burst.get("download_kbps")
            g.burst_upload_kbps = burst.get("upload_kbps")
            g.burst_threshold_kbps = burst.get("threshold_kbps")
            g.burst_time_seconds = burst.get("time_seconds")
        for key in ("name", "download_kbps", "upload_kbps", "priority", "notes"):
            if key in data and data[key] is not None:
                setattr(g, key, data[key])
        await self.session.flush()
        await self._propagate_group(isp, g)
        return g

    async def _propagate_group(self, isp: IspContext, g: IspSpeedGroup) -> None:
        """Push the new rate to every materialized QueueProfile of this
        group, through the existing profile update service. Applies at next
        login (X1) / next queue write; live sessions are not kicked."""
        if self.queue_service is None:
            return
        rows = (
            (
                await self.session.execute(
                    select(IspPackageMaterialization)
                    .join(
                        IspPackage,
                        IspPackage.id == IspPackageMaterialization.package_id,
                    )
                    .where(IspPackage.speed_group_id == g.id)
                )
            )
            .scalars()
            .all()
        )
        done: set[uuid.UUID] = set()
        for m in rows:
            if m.queue_profile_id not in done:
                await self.queue_service.update_profile(
                    m.queue_profile_id,
                    actor_user_id=isp.user_id,
                    requesting_organization_id=m.customer_organization_id,
                    download_rate_kbps=g.download_kbps,
                    upload_rate_kbps=g.upload_kbps,
                    burst_download_kbps=g.burst_download_kbps,
                    burst_upload_kbps=g.burst_upload_kbps,
                    burst_threshold_kbps=g.burst_threshold_kbps,
                    burst_time_seconds=g.burst_time_seconds,
                    priority=g.priority,
                )
                done.add(m.queue_profile_id)
            m.group_profile_version = (m.group_profile_version or 1) + 1
        await self.session.flush()

    async def set_group_status(
        self, isp: IspContext, group_id: uuid.UUID, status: str
    ) -> IspSpeedGroup:
        g = await self.group(isp, group_id)
        g.status = status
        await self.session.flush()
        return g

    async def delete_group(self, isp: IspContext, group_id: uuid.UUID) -> None:
        g = await self.group(isp, group_id)
        view = (await self.group_views(isp, [g]))[0]
        if not view["can_delete"]:
            raise IspGroupInUseError()
        g.mark_deleted()
        await self.session.flush()

    # ------------------------------------------------------------------
    # packages
    # ------------------------------------------------------------------
    async def _package_counts(self, package_ids: list[uuid.UUID]) -> tuple[dict, dict]:
        from app.domains.voucher.models import Voucher

        coupons: dict[uuid.UUID, dict] = {}
        subs: dict = {}
        if not package_ids:
            return coupons, subs
        rows = await self.session.execute(
            select(IspCouponBatch.package_id, Voucher.status, func.count())
            .join(
                IspCouponBatchPart,
                IspCouponBatchPart.coupon_batch_id == IspCouponBatch.id,
            )
            .join(Voucher, Voucher.batch_id == IspCouponBatchPart.voucher_batch_id)
            .where(IspCouponBatch.package_id.in_(package_ids))
            .group_by(IspCouponBatch.package_id, Voucher.status)
        )
        for pid, status, n in rows.all():
            bucket = coupons.setdefault(
                pid,
                {"unused": 0, "active": 0, "used_up": 0, "expired": 0, "revoked": 0},
            )
            bucket[COUPON_STATUS.get(status, status)] = bucket.get(
                COUPON_STATUS.get(status, status), 0
            ) + int(n)
        rows = await self.session.execute(
            select(IspSubscriber.package_id, func.count())
            .where(
                IspSubscriber.package_id.in_(package_ids),
                IspSubscriber.is_deleted.is_(False),
            )
            .group_by(IspSubscriber.package_id)
        )
        subs = dict(rows.all())
        return coupons, subs

    async def package_views(
        self, isp: IspContext, packages: list[IspPackage]
    ) -> list[dict]:
        groups = {}
        gids = list({p.speed_group_id for p in packages})
        if gids:
            groups = {
                g.id: g
                for g in (
                    await self.session.execute(
                        select(IspSpeedGroup).where(IspSpeedGroup.id.in_(gids))
                    )
                )
                .scalars()
                .all()
            }
        coupons, subs = await self._package_counts([p.id for p in packages])
        out = []
        for p in packages:
            g = groups.get(p.speed_group_id)
            c = coupons.get(
                p.id,
                {"unused": 0, "active": 0, "used_up": 0, "expired": 0, "revoked": 0},
            )
            in_use = (c["active"] + c["used_up"] + c["expired"]) > 0 or subs.get(
                p.id, 0
            ) > 0
            out.append(
                {
                    "id": str(p.id),
                    "name": p.name,
                    "speed_group": (
                        {
                            "id": str(g.id),
                            "name": g.name,
                            "download_kbps": g.download_kbps,
                            "upload_kbps": g.upload_kbps,
                        }
                        if g
                        else None
                    ),
                    "type": p.type,
                    "validity_days": p.validity_days,
                    "price_paise": p.price_paise,
                    "price_includes_gst": p.price_includes_gst,
                    "data_cap_mb": p.data_cap_mb,
                    "max_devices": p.max_devices,
                    "status": p.status,
                    "needs_price": p.needs_price,
                    "coupons": {
                        k: c.get(k, 0)
                        for k in ("unused", "active", "used_up", "expired")
                    },
                    "subscribers": int(subs.get(p.id, 0)),
                    "can_delete": not in_use,
                    "created_at": _iso(p.created_at),
                }
            )
        return out

    async def _in_use(self, p: IspPackage) -> bool:
        return not (await self.package_views(None, [p]))[0]["can_delete"]  # type: ignore[arg-type]

    async def list_packages(
        self,
        isp: IspContext,
        *,
        speed_group_id=None,
        type_=None,
        status=None,
        search=None,
        page=1,
        page_size=25,
    ) -> tuple[list[dict], int]:
        cond = [
            IspPackage.isp_organization_id == isp.isp_org_id,
            IspPackage.is_deleted.is_(False),
        ]
        if speed_group_id:
            cond.append(IspPackage.speed_group_id == speed_group_id)
        if type_:
            cond.append(IspPackage.type == type_)
        if status:
            cond.append(IspPackage.status == status)
        if search:
            cond.append(IspPackage.name.ilike(f"%{search.strip()}%"))
        total = (
            await self.session.execute(
                select(func.count()).select_from(IspPackage).where(*cond)
            )
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    select(IspPackage)
                    .where(*cond)
                    .order_by(IspPackage.name)
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.package_views(isp, list(rows)), int(total)

    async def create_package(
        self, isp: IspContext, data: dict, *, needs_price: bool = False
    ) -> IspPackage:
        g = await self.group(isp, data["speed_group_id"])
        if g.status != "active":
            raise IspPackageDisabledError("The speed group is disabled")
        validity = (
            data.get("validity_days")
            or (await self.plan_settings(isp))["default_validity_days"]
        )
        name = (data.get("name") or "").strip() or suggest_name(
            g.name, data["type"], validity
        )
        if await self._name_taken(IspPackage, isp, name):
            raise IspNameTakenError()
        p = IspPackage(
            isp_organization_id=isp.isp_org_id,
            speed_group_id=g.id,
            name=name,
            type=data["type"],
            validity_days=validity,
            price_paise=data.get("price_paise") or 0,
            price_includes_gst=data.get("price_includes_gst", True),
            data_cap_mb=data.get("data_cap_mb"),
            max_devices=data.get("max_devices") or 1,
            status="disabled" if needs_price else "active",
            needs_price=needs_price,
            created_by=isp.user_id,
        )
        self.session.add(p)
        await self.session.flush()
        return p

    async def update_package(
        self, isp: IspContext, package_id: uuid.UUID, data: dict
    ) -> IspPackage:
        p = await self.package(isp, package_id)
        if (
            "speed_group_id" in data and data["speed_group_id"] != p.speed_group_id
        ) or ("validity_days" in data and data["validity_days"] != p.validity_days):
            if await self._in_use(p):
                raise IspPackageInUseError()
            if "speed_group_id" in data:
                await self.group(isp, data["speed_group_id"])
        if data.get("name") and await self._name_taken(
            IspPackage, isp, data["name"], except_id=p.id
        ):
            raise IspNameTakenError()
        for key in (
            "name",
            "speed_group_id",
            "validity_days",
            "price_paise",
            "price_includes_gst",
            "data_cap_mb",
            "max_devices",
            "type",
        ):
            if key in data and (data[key] is not None or key == "data_cap_mb"):
                setattr(p, key, data[key])
        if "price_paise" in data and p.needs_price and (data["price_paise"] or 0) > 0:
            p.needs_price = False
        await self.session.flush()
        return p

    async def duplicate_package(
        self, isp: IspContext, package_id: uuid.UUID, data: dict
    ) -> IspPackage:
        p = await self.package(isp, package_id)
        return await self.create_package(
            isp,
            {
                "speed_group_id": p.speed_group_id,
                "type": p.type,
                "validity_days": data["validity_days"],
                "price_paise": data.get("price_paise", p.price_paise),
                "price_includes_gst": p.price_includes_gst,
                "data_cap_mb": p.data_cap_mb,
                "max_devices": p.max_devices,
                "name": data.get("name"),
            },
        )

    async def set_package_status(
        self, isp: IspContext, package_id: uuid.UUID, status: str
    ) -> IspPackage:
        p = await self.package(isp, package_id)
        if status == "active" and p.needs_price:
            raise IspPackageNeedsPriceError()
        p.status = status
        await self.session.flush()
        return p

    async def delete_package(self, isp: IspContext, package_id: uuid.UUID) -> None:
        p = await self.package(isp, package_id)
        if await self._in_use(p):
            raise IspPackageInUseError()
        for batch in (
            (
                await self.session.execute(
                    select(IspCouponBatch).where(IspCouponBatch.package_id == p.id)
                )
            )
            .scalars()
            .all()
        ):
            await self._revoke_unused(batch)
            batch.status = "revoked"
        p.mark_deleted()
        await self.session.flush()

    async def ladder(self, isp: IspContext, data: dict) -> dict:
        created_groups = created_packages = 0
        skipped: list[str] = []
        prices = data.get("prices_paise") or {}
        for mbps in data["speeds_mbps"]:
            name = f"{mbps} Mbps"
            group = (
                await self.session.execute(
                    select(IspSpeedGroup).where(
                        IspSpeedGroup.isp_organization_id == isp.isp_org_id,
                        func.lower(IspSpeedGroup.name) == name.lower(),
                        IspSpeedGroup.deleted_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if group is None:
                kbps = int(mbps * KBPS_PER_MBPS)
                group = await self.create_group(
                    isp,
                    {
                        "name": name,
                        "download_kbps": kbps,
                        "upload_kbps": kbps
                        if data.get("upload_equals_download", True)
                        else max(64, kbps // 2),
                    },
                )
                created_groups += 1
            for days in data["validities_days"]:
                pname = suggest_name(group.name, data.get("type", "prepaid"), days)
                if await self._name_taken(IspPackage, isp, pname):
                    skipped.append(pname)
                    continue
                price = prices.get(f"{mbps}:{days}")
                await self.create_package(
                    isp,
                    {
                        "speed_group_id": group.id,
                        "type": data.get("type", "prepaid"),
                        "validity_days": days,
                        "price_paise": price or 0,
                        "name": pname,
                    },
                    needs_price=not price,
                )
                created_packages += 1
        return {
            "created_groups": created_groups,
            "created_packages": created_packages,
            "skipped": skipped,
        }

    # ------------------------------------------------------------------
    # materialization
    # ------------------------------------------------------------------
    async def materialize(
        self, isp: IspContext, package: IspPackage, customer_id: uuid.UUID
    ) -> IspPackageMaterialization:
        await IspScope.assert_customer(isp, customer_id)
        existing = (
            await self.session.execute(
                select(IspPackageMaterialization).where(
                    IspPackageMaterialization.package_id == package.id,
                    IspPackageMaterialization.customer_organization_id == customer_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        group = await self.session.get(IspSpeedGroup, package.speed_group_id)
        # One QueueProfile per (group, customer): reuse a sibling package's.
        sibling = (
            await self.session.execute(
                select(IspPackageMaterialization.queue_profile_id)
                .join(IspPackage, IspPackage.id == IspPackageMaterialization.package_id)
                .where(
                    IspPackage.speed_group_id == group.id,
                    IspPackageMaterialization.customer_organization_id == customer_id,
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if sibling is None:
            profile = await self.queue_service.create_profile(
                actor_user_id=isp.user_id,
                requesting_organization_id=customer_id,
                name=f"isp-sg-{group.id.hex[:8]}",
                description=f"ISP speed group {group.name}",
                download_rate_kbps=group.download_kbps,
                upload_rate_kbps=group.upload_kbps,
                burst_download_kbps=group.burst_download_kbps,
                burst_upload_kbps=group.burst_upload_kbps,
                burst_threshold_kbps=group.burst_threshold_kbps,
                burst_time_seconds=group.burst_time_seconds,
                priority=group.priority,
            )
            sibling = profile.id
        plan = await self.voucher_service.create_plan(
            actor_user_id=isp.user_id,
            requesting_organization_id=customer_id,
            organization_id=customer_id,
            name=f"isp-pkg-{package.id.hex[:8]}",
            description=package.name[:255],
            queue_profile_id=sibling,
            default_validity_minutes=package.validity_days * 1440,
            default_data_limit_mb=package.data_cap_mb,
            default_max_uses_per_voucher=VOUCHER_BATCH_MAX,
        )
        row = IspPackageMaterialization(
            package_id=package.id,
            customer_organization_id=customer_id,
            queue_profile_id=sibling,
            voucher_plan_id=plan.id,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    # ------------------------------------------------------------------
    # coupons
    # ------------------------------------------------------------------
    async def _voucher_query(self, batch: IspCouponBatch):  # noqa: ANN202
        from app.domains.voucher.models import Voucher

        parts = select(IspCouponBatchPart.voucher_batch_id).where(
            IspCouponBatchPart.coupon_batch_id == batch.id
        )
        return select(Voucher).where(Voucher.batch_id.in_(parts)).order_by(Voucher.code)

    async def _all_coupons(self, batch: IspCouponBatch) -> list[tuple[str, Any]]:
        rows = (
            (await self.session.execute(await self._voucher_query(batch)))
            .scalars()
            .all()
        )
        return [
            (f"{batch.serial_prefix}-{batch.batch_seq:04d}-{n:04d}", v)
            for n, v in enumerate(rows, start=1)
        ]

    async def coupon_login_disabled(
        self, customer_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[dict]:
        from app.domains.captive_portal.models import CaptivePortalConfig
        from app.domains.location.models import Location

        q = select(Location).where(
            Location.organization_id == customer_id, Location.is_deleted.is_(False)
        )
        if location_id is not None:
            q = q.where(Location.id == location_id)
        out = []
        for loc in (await self.session.execute(q)).scalars().all():
            enabled = (
                await self.session.execute(
                    select(func.count()).where(
                        CaptivePortalConfig.location_id == loc.id,
                        CaptivePortalConfig.is_active.is_(True),
                        CaptivePortalConfig.voucher_enabled.is_(True),
                        CaptivePortalConfig.is_deleted.is_(False),
                    )
                )
            ).scalar_one()
            if not enabled:
                out.append({"isp_location_id": str(loc.id), "name": loc.name})
        return out

    async def create_coupon_batch(
        self, isp: IspContext, data: dict, *, is_cut
    ) -> tuple[IspCouponBatch, list[dict]]:  # noqa: ANN001
        from .exceptions import IspCustomerSuspendedError, IspLocationNotFoundError

        package = await self.package(isp, data["package_id"])
        if package.status != "active":
            raise IspPackageDisabledError()
        if package.needs_price:
            raise IspPackageNeedsPriceError()
        group = await self.session.get(IspSpeedGroup, package.speed_group_id)
        if group.status != "active":
            raise IspPackageDisabledError("The speed group is disabled")
        customer = await IspScope.assert_customer(isp, data["isp_customer_id"])
        if customer.status != "active" or await is_cut(customer.id):
            raise IspCustomerSuspendedError()
        location_id = None
        if data.get("isp_location_id"):
            loc = await IspScope.assert_location(isp, data["isp_location_id"])
            if loc.organization_id != customer.id:
                raise IspLocationNotFoundError()
            location_id = loc.id
        mat = await self.materialize(isp, package, customer.id)
        seq = await IspBillingService(session=self.session)._allocate(
            isp.isp_org_id, "coupon_batch", "----"
        )
        prefix = (
            data.get("serial_prefix")
            or "".join(ch for ch in isp.organization.slug.upper() if ch.isalnum())[:4]
            or "ISP"
        )[:12]
        now = self._clock()
        shelf = now + timedelta(days=data.get("shelf_life_days") or 365)
        batch = IspCouponBatch(
            isp_organization_id=isp.isp_org_id,
            package_id=package.id,
            customer_organization_id=customer.id,
            location_id=location_id,
            batch_seq=seq,
            serial_prefix=prefix,
            quantity=data["quantity"],
            shelf_life_until=shelf,
            status="active",
            created_by=isp.user_id,
        )
        self.session.add(batch)
        await self.session.flush()
        remaining = data["quantity"]
        parts = math.ceil(remaining / VOUCHER_BATCH_MAX)
        for i in range(parts):
            qty = min(VOUCHER_BATCH_MAX, remaining)
            remaining -= qty
            vb = await self.voucher_service.create_batch(
                actor_user_id=isp.user_id,
                requesting_organization_id=customer.id,
                organization_id=customer.id,
                location_id=location_id,
                name=f"{prefix}-{seq:04d} {package.name}"[:150]
                + (f" ({i + 1}/{parts})" if parts > 1 else ""),
                quantity=qty,
                code_length=data.get("code_length") or 10,
                code_prefix=data.get("code_prefix"),
                validity_minutes=package.validity_days * 1440,
                batch_expires_at=shelf,
                max_uses_per_voucher=VOUCHER_BATCH_MAX,
                data_limit_mb=package.data_cap_mb,
                notes=f"ISP coupon batch {batch.id}",
                has_manage_permission=True,
                plan_id=mat.voucher_plan_id,
            )
            self.session.add(
                IspCouponBatchPart(
                    coupon_batch_id=batch.id,
                    voucher_batch_id=vb.id,
                    part_index=i,
                    quantity=qty,
                )
            )
        await self.session.flush()
        warnings = await self.coupon_login_disabled(customer.id, location_id)
        return batch, warnings

    async def batch_views(
        self, isp: IspContext, batches: list[IspCouponBatch]
    ) -> list[dict]:
        from app.domains.location.models import Location
        from app.domains.organization.models import Organization
        from app.domains.voucher.models import Voucher

        orgs = await isp.repository.names(
            Organization, [b.customer_organization_id for b in batches]
        )
        locs = await isp.repository.names(
            Location, [b.location_id for b in batches if b.location_id]
        )
        pkgs = {}
        pids = list({b.package_id for b in batches})
        if pids:
            pkgs = {
                p.id: p
                for p in (
                    await self.session.execute(
                        select(IspPackage).where(IspPackage.id.in_(pids))
                    )
                )
                .scalars()
                .all()
            }
        counts: dict = {}
        if batches:
            rows = await self.session.execute(
                select(IspCouponBatchPart.coupon_batch_id, Voucher.status, func.count())
                .join(Voucher, Voucher.batch_id == IspCouponBatchPart.voucher_batch_id)
                .where(IspCouponBatchPart.coupon_batch_id.in_([b.id for b in batches]))
                .group_by(IspCouponBatchPart.coupon_batch_id, Voucher.status)
            )
            for bid, status, n in rows.all():
                c = counts.setdefault(
                    bid,
                    {
                        "unused": 0,
                        "active": 0,
                        "used_up": 0,
                        "expired": 0,
                        "revoked": 0,
                    },
                )
                c[COUPON_STATUS.get(status, status)] += int(n)
        return [
            {
                "id": str(b.id),
                "package": {
                    "id": str(b.package_id),
                    "name": pkgs[b.package_id].name if b.package_id in pkgs else None,
                },
                "isp_customer_id": str(b.customer_organization_id),
                "customer_name": orgs.get(b.customer_organization_id),
                "isp_location_id": str(b.location_id) if b.location_id else None,
                "location_name": locs.get(b.location_id) if b.location_id else None,
                "quantity": b.quantity,
                "serial_prefix": b.serial_prefix,
                "batch_seq": b.batch_seq,
                "shelf_life_until": _iso(b.shelf_life_until),
                "status": b.status,
                "counts": counts.get(
                    b.id,
                    {
                        "unused": 0,
                        "active": 0,
                        "used_up": 0,
                        "expired": 0,
                        "revoked": 0,
                    },
                ),
                "created_at": _iso(b.created_at),
            }
            for b in batches
        ]

    async def list_batches(
        self,
        isp: IspContext,
        *,
        package_id=None,
        isp_customer_id=None,
        status=None,
        page=1,
        page_size=25,
    ) -> tuple[list[dict], int]:
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        if not ids:
            return [], 0
        cond = [
            IspCouponBatch.isp_organization_id == isp.isp_org_id,
            IspCouponBatch.customer_organization_id.in_(ids),
            IspCouponBatch.is_deleted.is_(False),
        ]
        if package_id:
            cond.append(IspCouponBatch.package_id == package_id)
        if status:
            cond.append(IspCouponBatch.status == status)
        total = (
            await self.session.execute(
                select(func.count()).select_from(IspCouponBatch).where(*cond)
            )
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    select(IspCouponBatch)
                    .where(*cond)
                    .order_by(IspCouponBatch.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.batch_views(isp, list(rows)), int(total)

    @staticmethod
    def coupon_view(serial: str, v: Any) -> dict:
        return {
            "id": str(v.id),
            "serial": serial,
            "code": v.code,
            "status": COUPON_STATUS.get(v.status, v.status),
            "redeemed_by": mask_identifier(v.redeemed_identifier)
            if v.redeemed_identifier
            else None,
            "activated_at": _iso(v.redeemed_at),
            "expires_at": _iso(v.expires_at),
        }

    async def list_coupons(
        self,
        isp: IspContext,
        batch_id: uuid.UUID,
        *,
        status=None,
        search=None,
        page=1,
        page_size=25,
    ) -> tuple[list[dict], int]:
        batch = await self.coupon_batch(isp, batch_id)
        rows = [self.coupon_view(s, v) for s, v in await self._all_coupons(batch)]
        if status:
            rows = [r for r in rows if r["status"] == status]
        if search:
            needle = search.strip().upper()
            rows = [
                r
                for r in rows
                if needle in r["serial"].upper() or needle in r["code"].upper()
            ]
        return rows[(page - 1) * page_size : page * page_size], len(rows)

    async def _revoke_unused(
        self,
        batch: IspCouponBatch,
        *,
        voucher_id: uuid.UUID | None = None,
        include_active: bool = False,
    ) -> int:
        from app.domains.voucher.models import Voucher

        parts = select(IspCouponBatchPart.voucher_batch_id).where(
            IspCouponBatchPart.coupon_batch_id == batch.id
        )
        statuses = ["unused", "active"] if include_active else ["unused"]
        stmt = (
            update(Voucher)
            .where(Voucher.batch_id.in_(parts), Voucher.status.in_(statuses))
            .values(status="revoked")
        )
        if voucher_id is not None:
            stmt = stmt.where(Voucher.id == voucher_id)
        result = await self.session.execute(
            stmt.execution_options(synchronize_session=False)
        )
        return int(result.rowcount or 0)

    async def revoke_batch(self, isp: IspContext, batch_id: uuid.UUID) -> dict:
        batch = await self.coupon_batch(isp, batch_id)
        n = await self._revoke_unused(batch)
        batch.status = "revoked"
        await self.session.flush()
        return {**(await self.batch_views(isp, [batch]))[0], "revoked": n}

    async def revoke_coupon(self, isp: IspContext, coupon_id: uuid.UUID) -> dict:
        from app.domains.voucher.models import Voucher

        v = await self.session.get(Voucher, coupon_id)
        if v is None:
            raise IspCouponNotFoundError()
        part = (
            await self.session.execute(
                select(IspCouponBatchPart).where(
                    IspCouponBatchPart.voucher_batch_id == v.batch_id
                )
            )
        ).scalar_one_or_none()
        if part is None:
            raise IspCouponNotFoundError()
        try:
            batch = await self.coupon_batch(isp, part.coupon_batch_id)
        except IspCouponBatchNotFoundError:
            raise IspCouponNotFoundError() from None
        await self._revoke_unused(batch, voucher_id=v.id, include_active=True)
        await self.session.refresh(v)
        serial = next(
            (s for s, x in await self._all_coupons(batch) if x.id == v.id), None
        )
        return self.coupon_view(serial or "", v)

    # ------------------------------------------------------------------
    # subscribers
    # ------------------------------------------------------------------
    async def sync_subscribers(self, isp: IspContext, *, force: bool = False) -> int:
        """Derive subscribers from redeemed ISP coupons (no hook into old
        code). Idempotent; throttled to once a minute per ISP."""
        from app.domains.guest.models import Guest
        from app.domains.voucher.models import Voucher

        now = self._clock()
        last = _last_sync.get(isp.isp_org_id)
        if not force and last and now - last < SYNC_MIN_INTERVAL:
            return 0
        _last_sync[isp.isp_org_id] = now
        rows = (
            await self.session.execute(
                select(Voucher, IspCouponBatch)
                .join(
                    IspCouponBatchPart,
                    IspCouponBatchPart.voucher_batch_id == Voucher.batch_id,
                )
                .join(
                    IspCouponBatch,
                    IspCouponBatch.id == IspCouponBatchPart.coupon_batch_id,
                )
                .where(
                    IspCouponBatch.isp_organization_id == isp.isp_org_id,
                    Voucher.redeemed_at.is_not(None),
                    Voucher.redeemed_identifier.is_not(None),
                    Voucher.organization_id == IspCouponBatch.customer_organization_id,
                )
                .order_by(Voucher.redeemed_at)
            )
        ).all()
        if not rows:
            return 0
        existing = {
            (s.customer_organization_id, s.identifier): s
            for s in (
                await self.session.execute(
                    select(IspSubscriber).where(
                        IspSubscriber.isp_organization_id == isp.isp_org_id,
                        IspSubscriber.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        }
        last_redeemed = {}
        for s in existing.values():
            if s.last_voucher_id:
                last_redeemed[s.id] = None
        packages = {
            p.id: p
            for p in (
                await self.session.execute(
                    select(IspPackage).where(
                        IspPackage.isp_organization_id == isp.isp_org_id
                    )
                )
            )
            .scalars()
            .all()
        }
        changed = 0
        voucher_time = {v.id: v.redeemed_at for v, _ in rows}
        for v, batch in rows:
            key = (batch.customer_organization_id, v.redeemed_identifier)
            sub = existing.get(key)
            pkg = packages.get(batch.package_id)
            if sub is None:
                guest = (
                    await self.session.execute(
                        select(Guest.id)
                        .where(
                            Guest.organization_id == batch.customer_organization_id,
                            Guest.identifier == v.redeemed_identifier,
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
                sub = IspSubscriber(
                    isp_organization_id=isp.isp_org_id,
                    customer_organization_id=batch.customer_organization_id,
                    identifier=v.redeemed_identifier,
                    package_id=batch.package_id,
                    speed_group_id=pkg.speed_group_id if pkg else None,
                    valid_until=v.expires_at,
                    status="active",
                    source="coupon",
                    last_voucher_id=v.id,
                    guest_id=guest,
                )
                self.session.add(sub)
                existing[key] = sub
                changed += 1
                continue
            if sub.last_voucher_id == v.id:
                continue
            prev = voucher_time.get(sub.last_voucher_id)
            if prev is None or v.redeemed_at >= prev:
                # top-up: a newer redemption extends from that coupon's own first use
                sub.last_voucher_id = v.id
                sub.package_id = batch.package_id
                sub.speed_group_id = pkg.speed_group_id if pkg else sub.speed_group_id
                if v.expires_at and (
                    sub.valid_until is None or v.expires_at > sub.valid_until
                ):
                    sub.valid_until = v.expires_at
                if sub.status != "disabled":
                    sub.status = "active"
                changed += 1
        for sub in existing.values():
            if sub.status == "active" and sub.valid_until and sub.valid_until < now:
                sub.status = "expired"
        await self.session.flush()
        return changed

    async def subscriber_views(
        self, isp: IspContext, subs: list[IspSubscriber]
    ) -> list[dict]:
        from app.domains.guest.models import Guest
        from app.domains.organization.models import Organization

        orgs = await isp.repository.names(
            Organization, [s.customer_organization_id for s in subs]
        )
        pkgs = {}
        groups = {}
        pids = list({s.package_id for s in subs if s.package_id})
        gids = list({s.speed_group_id for s in subs if s.speed_group_id})
        if pids:
            pkgs = {
                p.id: p
                for p in (
                    await self.session.execute(
                        select(IspPackage).where(IspPackage.id.in_(pids))
                    )
                )
                .scalars()
                .all()
            }
        if gids:
            groups = {
                g.id: g
                for g in (
                    await self.session.execute(
                        select(IspSpeedGroup).where(IspSpeedGroup.id.in_(gids))
                    )
                )
                .scalars()
                .all()
            }
        seen = {}
        guest_ids = [s.guest_id for s in subs if s.guest_id]
        if guest_ids:
            seen = dict(
                (
                    await self.session.execute(
                        select(Guest.id, Guest.last_seen_at).where(
                            Guest.id.in_(guest_ids)
                        )
                    )
                ).all()
            )
        return [
            {
                "id": str(s.id),
                "isp_customer_id": str(s.customer_organization_id),
                "customer_name": orgs.get(s.customer_organization_id),
                "identifier": mask_identifier(s.identifier),
                "display_name": s.display_name,
                "package": {"id": str(s.package_id), "name": pkgs[s.package_id].name}
                if s.package_id in pkgs
                else None,
                "speed_group": {
                    "id": str(s.speed_group_id),
                    "name": groups[s.speed_group_id].name,
                }
                if s.speed_group_id in groups
                else None,
                "valid_until": _iso(s.valid_until),
                "status": s.status,
                "source": s.source,
                "last_seen_at": _iso(seen.get(s.guest_id)) if s.guest_id else None,
            }
            for s in subs
        ]

    async def list_subscribers(
        self,
        isp: IspContext,
        *,
        isp_customer_id=None,
        speed_group_id=None,
        package_id=None,
        status=None,
        search=None,
        page=1,
        page_size=25,
    ) -> tuple[list[dict], int]:
        await self.sync_subscribers(isp)
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        if not ids:
            return [], 0
        cond = [
            IspSubscriber.isp_organization_id == isp.isp_org_id,
            IspSubscriber.customer_organization_id.in_(ids),
            IspSubscriber.is_deleted.is_(False),
        ]
        if speed_group_id:
            cond.append(IspSubscriber.speed_group_id == speed_group_id)
        if package_id:
            cond.append(IspSubscriber.package_id == package_id)
        if status:
            cond.append(IspSubscriber.status == status)
        if search:
            pattern = f"%{search.strip()}%"
            cond.append(
                or_(
                    IspSubscriber.identifier.ilike(pattern),
                    IspSubscriber.display_name.ilike(pattern),
                )
            )
        total = (
            await self.session.execute(
                select(func.count()).select_from(IspSubscriber).where(*cond)
            )
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    select(IspSubscriber)
                    .where(*cond)
                    .order_by(IspSubscriber.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.subscriber_views(isp, list(rows)), int(total)

    async def subscriber_detail(
        self, isp: IspContext, subscriber_id: uuid.UUID
    ) -> dict:
        from app.domains.guest.models import GuestSession
        from app.domains.location.models import Location
        from app.domains.voucher.models import Voucher

        s = await self.subscriber(isp, subscriber_id)
        view = (await self.subscriber_views(isp, [s]))[0]
        history = (
            await self.session.execute(
                select(Voucher, IspPackage.name)
                .join(
                    IspCouponBatchPart,
                    IspCouponBatchPart.voucher_batch_id == Voucher.batch_id,
                )
                .join(
                    IspCouponBatch,
                    IspCouponBatch.id == IspCouponBatchPart.coupon_batch_id,
                )
                .join(IspPackage, IspPackage.id == IspCouponBatch.package_id)
                .where(
                    IspCouponBatch.customer_organization_id
                    == s.customer_organization_id,
                    Voucher.redeemed_identifier == s.identifier,
                )
                .order_by(Voucher.redeemed_at.desc())
            )
        ).all()
        view["coupon_history"] = [
            {
                "serial": None,
                "coupon_id": str(v.id),
                "package_name": name,
                "activated_at": _iso(v.redeemed_at),
                "expires_at": _iso(v.expires_at),
            }
            for v, name in history
        ]
        sessions = []
        if s.guest_id:
            rows = (
                await self.session.execute(
                    select(GuestSession, Location.name)
                    .outerjoin(Location, Location.id == GuestSession.location_id)
                    .where(
                        GuestSession.guest_id == s.guest_id,
                        GuestSession.organization_id == s.customer_organization_id,
                    )
                    .order_by(GuestSession.started_at.desc())
                    .limit(20)
                )
            ).all()
            sessions = [
                {
                    "id": str(g.id),
                    "started_at": _iso(g.started_at),
                    "ended_at": _iso(g.ended_at),
                    "location_name": ln,
                    "bytes_uploaded": int(g.bytes_uploaded or 0),
                    "bytes_downloaded": int(g.bytes_downloaded or 0),
                }
                for g, ln in rows
            ]
        view["recent_sessions"] = sessions
        return view

    async def create_subscriber(self, isp: IspContext, data: dict) -> IspSubscriber:
        customer = await IspScope.assert_customer(isp, data["isp_customer_id"])
        package = await self.package(isp, data["package_id"])
        if package.status != "active":
            raise IspPackageDisabledError()
        await self.materialize(isp, package, customer.id)
        start = data.get("valid_from") or self._clock()
        existing = (
            await self.session.execute(
                select(IspSubscriber).where(
                    IspSubscriber.customer_organization_id == customer.id,
                    IspSubscriber.identifier == data["identifier"].strip(),
                    IspSubscriber.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise IspNameTakenError("A subscriber with that identifier already exists")
        s = IspSubscriber(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=customer.id,
            identifier=data["identifier"].strip(),
            display_name=data.get("display_name"),
            package_id=package.id,
            speed_group_id=package.speed_group_id,
            valid_until=start + timedelta(days=package.validity_days),
            status="active",
            source="manual",
            created_by=isp.user_id,
        )
        self.session.add(s)
        await self.session.flush()
        return s

    async def update_subscriber(
        self, isp: IspContext, subscriber_id: uuid.UUID, data: dict
    ) -> IspSubscriber:
        s = await self.subscriber(isp, subscriber_id)
        if data.get("package_id"):
            package = await self.package(isp, data["package_id"])
            await self.materialize(isp, package, s.customer_organization_id)
            s.package_id = package.id
            s.speed_group_id = package.speed_group_id
        if "valid_until" in data and data["valid_until"] is not None:
            s.valid_until = data["valid_until"]
            if s.status == "expired" and s.valid_until > self._clock():
                s.status = "active"
        if "display_name" in data:
            s.display_name = data["display_name"]
        await self.session.flush()
        return s

    async def set_subscriber_status(
        self, isp: IspContext, subscriber_id: uuid.UUID, enabled: bool
    ) -> IspSubscriber:
        s = await self.subscriber(isp, subscriber_id)
        if enabled:
            s.status = (
                "active"
                if not s.valid_until or s.valid_until > self._clock()
                else "expired"
            )
        else:
            s.status = "disabled"
        await self.session.flush()
        return s

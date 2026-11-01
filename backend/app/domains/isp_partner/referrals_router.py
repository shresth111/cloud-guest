"""REFERRAL-1 routes (``/isp/referrals``), behind ``ISP_REFERRALS_ENABLED``
(default OFF). Keys: ``isp_referrals.read`` / ``.create`` (record, cancel) /
``.manage`` (settings; owner/admin)."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .referrals_config import (
    ISP_REFERRALS_CREATE,
    ISP_REFERRALS_MANAGE,
    ISP_REFERRALS_READ,
    RequireReferralsEnabled,
)
from .referrals_service import IspReferralsService

referrals_router = APIRouter(prefix="/referrals", tags=["ISP Partner: referrals"])
_ON = [Depends(RequireReferralsEnabled)]


def get_referrals_service(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspReferralsService:
    return IspReferralsService(session=db, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RefCreateRequest(_Body):
    referrer_subscriber_id: uuid.UUID
    referred_subscriber_id: uuid.UUID
    note: str | None = Field(default=None, max_length=500)


class RefCancelRequest(_Body):
    reason: str = Field(min_length=3, max_length=255)


class RefSettingsRequest(_Body):
    enabled: bool | None = None
    reward_paise: int | None = Field(default=None, ge=0, le=10_000_00)
    max_rewards_per_year: int | None = Field(default=None, ge=0, le=365)
    window_days: int | None = Field(default=None, ge=1, le=365)
    min_first_invoice_paise: int | None = Field(default=None, ge=0, le=10_000_000_00)


@referrals_router.get("/settings", dependencies=_ON + isp_guards(ISP_REFERRALS_READ))
async def get_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspReferralsService = Depends(get_referrals_service),
) -> dict:
    row = await svc.settings_row(isp.isp_org_id)
    return ok(request, svc.settings_view(row), "Referral settings")


@referrals_router.put("/settings", dependencies=_ON + isp_guards(ISP_REFERRALS_MANAGE))
async def put_settings(
    request: Request,
    body: RefSettingsRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspReferralsService = Depends(get_referrals_service),
) -> dict:
    out = await svc.put_settings(isp, body.model_dump(exclude_none=True))
    await svc.session.commit()
    return ok(request, out, "Referral settings saved")


@referrals_router.get("", dependencies=_ON + isp_guards(ISP_REFERRALS_READ))
async def list_referrals(
    request: Request,
    status: Literal["pending", "earned", "applied", "rejected", "cancelled"]
    | None = None,
    subscriber_id: uuid.UUID | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspReferralsService = Depends(get_referrals_service),
) -> dict:
    data = await svc.list(
        isp, status=status, subscriber_id=subscriber_id, page=page, page_size=page_size
    )
    return ok(request, data, "Referrals")


@referrals_router.post(
    "", status_code=201, dependencies=_ON + isp_guards(ISP_REFERRALS_CREATE)
)
async def create_referral(
    request: Request,
    body: RefCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspReferralsService = Depends(get_referrals_service),
) -> dict:
    out = await svc.create(isp, **body.model_dump())
    await svc.session.commit()
    return ok(request, out, "Referral recorded")


@referrals_router.get(
    "/{referral_id}", dependencies=_ON + isp_guards(ISP_REFERRALS_READ)
)
async def get_referral(
    request: Request,
    referral_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspReferralsService = Depends(get_referrals_service),
) -> dict:
    r = await svc.referral(isp, referral_id)
    return ok(request, (await svc.views(isp, [r]))[0], "Referral")


@referrals_router.post(
    "/{referral_id}/cancel", dependencies=_ON + isp_guards(ISP_REFERRALS_CREATE)
)
async def cancel_referral(
    request: Request,
    referral_id: uuid.UUID,
    body: RefCancelRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspReferralsService = Depends(get_referrals_service),
) -> dict:
    out = await svc.cancel(isp, referral_id, body.reason)
    await svc.session.commit()
    return ok(request, out, "Referral cancelled")


__all__ = ["referrals_router"]

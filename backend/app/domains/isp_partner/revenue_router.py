"""REVENUE-HUB + CHURN-RISK routes (read-only), behind
``ISP_REVENUE_HUB_ENABLED`` (default OFF: every route answers 404
``ISP_REVENUE_HUB_DISABLED``).

Keys: aggregates (``/revenue/summary``, ``/revenue/churn-risk/summary``,
``/revenue/probe``) need ``isp_billing.read``, so the ISP Viewer sees them.
Anything that names a subscriber (``/revenue/list``, ``/revenue/churn-risk``)
needs ``isp_billing.export`` (owner / admin / billing; not viewer), the key
RBAC-FIX already uses for PII-bearing billing reads. Zone scope comes from
ZONE-1's ``scope_zone_id`` (applied in ``RequireIspPartner``); confinement
always applies. Win-back actions are the existing endpoints (360 profile +
renew, JAZE-5 tickets, the JAZE-4 pay link); nothing here writes.
"""

from __future__ import annotations

import uuid
from functools import lru_cache

from fastapi import APIRouter, Depends, Query, Request
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from . import revenue_logic as logic
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import _err
from .http import ok
from .revenue_service import IspRevenueService, RevFilters

BILLING_READ = "isp_billing.read"
BILLING_EXPORT = "isp_billing.export"


class IspRevenueSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    revenue_hub_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_revenue_settings() -> IspRevenueSettings:
    return IspRevenueSettings()


IspRevenueHubDisabledError = _err(
    "IspRevenueHubDisabledError", "ISP_REVENUE_HUB_DISABLED", 404, "Not Found"
)


async def RequireRevenueHubEnabled() -> None:
    if not get_revenue_settings().revenue_hub_enabled:
        raise IspRevenueHubDisabledError()


revenue_router = APIRouter(tags=["ISP Partner: revenue hub"])
_ON = [Depends(RequireRevenueHubEnabled)]
_METRIC = "^(" + "|".join(logic.LIST_METRICS) + ")$"
_REASON = "^(" + "|".join(logic.RISK_REASONS) + ")$"


def _filters(
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$"),
    months: int = Query(default=6, ge=1, le=24),
    zone_id: uuid.UUID | None = Query(default=None),
    no_zone: bool = Query(default=False),
    package_id: uuid.UUID | None = Query(default=None),
) -> RevFilters:
    return RevFilters(
        month=month,
        months=months,
        zone_id=zone_id,
        no_zone=no_zone,
        package_id=package_id,
    )


@revenue_router.get("/revenue/probe", dependencies=_ON + isp_guards(BILLING_READ))
async def revenue_probe(
    request: Request, isp: IspContext = Depends(RequireIspPartner)
) -> dict:
    """FE probe: 200 while the flag is on (the nav item shows), 404 off."""
    return ok(request, {"enabled": True}, "Revenue hub")


@revenue_router.get("/revenue/summary", dependencies=_ON + isp_guards(BILLING_READ))
async def revenue_summary(
    request: Request,
    f: RevFilters = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(request, await IspRevenueService(db).summary(isp, f), "Revenue hub")


@revenue_router.get("/revenue/list", dependencies=_ON + isp_guards(BILLING_EXPORT))
async def revenue_list(
    request: Request,
    metric: str = Query(pattern=_METRIC),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    f: RevFilters = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request,
        await IspRevenueService(db).drill(
            isp, f, metric=metric, page=page, page_size=page_size
        ),
        "Revenue drill-down",
    )


@revenue_router.get(
    "/revenue/churn-risk/summary", dependencies=_ON + isp_guards(BILLING_READ)
)
async def churn_risk_summary(
    request: Request,
    f: RevFilters = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request, await IspRevenueService(db).risk_summary(isp, f), "Churn risk counts"
    )


@revenue_router.get(
    "/revenue/churn-risk", dependencies=_ON + isp_guards(BILLING_EXPORT)
)
async def churn_risk_list(
    request: Request,
    reason: str | None = Query(default=None, pattern=_REASON),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    f: RevFilters = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request,
        await IspRevenueService(db).churn_risk(
            isp, f, reason=reason, page=page, page_size=page_size
        ),
        "Subscribers at risk",
    )


__all__ = ["get_revenue_settings", "revenue_router"]

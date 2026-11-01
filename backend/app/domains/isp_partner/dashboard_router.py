"""DASH-1 routes: subscriber operations dashboard + its drill-down.

``ISP_DASHBOARD_ENABLED`` (default OFF): 404 ``ISP_DASHBOARD_DISABLED`` while
off, and the overview keeps JAZE-3's counters. Zone scope comes from ZONE-1's
``scope_zone_id`` (applied in ``RequireIspPartner``); confinement always
applies. Dates are plain ``YYYY-MM-DD``.
"""

from __future__ import annotations

import uuid
from datetime import date
from functools import lru_cache

from fastapi import APIRouter, Depends, Query, Request
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dashboard_logic import TILE_KEYS
from .dashboard_service import Filters, IspDashboardService
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import _err
from .http import ok

SUBS_READ = "isp_subscribers.read"


class IspDashboardSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    dashboard_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_dashboard_settings() -> IspDashboardSettings:
    return IspDashboardSettings()


IspDashboardDisabledError = _err(
    "IspDashboardDisabledError", "ISP_DASHBOARD_DISABLED", 404, "Not Found"
)


async def RequireDashboardEnabled() -> None:
    if not get_dashboard_settings().dashboard_enabled:
        raise IspDashboardDisabledError()


dashboard_router = APIRouter(tags=["ISP Partner: dashboard"])
_ON = [Depends(RequireDashboardEnabled)]
_TILE_PATTERN = "^(" + "|".join(TILE_KEYS) + ")$"


def _filters(
    period: str = Query(default="7d", pattern="^(today|7d|30d|custom)$"),
    date_from: date | None = Query(default=None),
    date_to: date | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    package_id: uuid.UUID | None = Query(default=None),
    connection_type: str | None = Query(default=None, max_length=12),
) -> Filters:
    return Filters(
        period=period,
        date_from=date_from,
        date_to=date_to,
        router_id=isp_router_id,
        package_id=package_id,
        connection_type=connection_type or None,
    )


@dashboard_router.get(
    "/dashboard/subscribers", dependencies=_ON + isp_guards(SUBS_READ)
)
async def dashboard_subscribers(
    request: Request,
    f: Filters = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request, await IspDashboardService(db).summary(isp, f), "Subscriber dashboard"
    )


@dashboard_router.get(
    "/dashboard/subscribers/list", dependencies=_ON + isp_guards(SUBS_READ)
)
async def dashboard_subscribers_list(
    request: Request,
    tile: str = Query(pattern=_TILE_PATTERN),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    f: Filters = Depends(_filters),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request,
        await IspDashboardService(db).drill(
            isp, f, tile=tile, page=page, page_size=page_size
        ),
        "Subscribers in this tile",
    )


__all__ = ["dashboard_router", "get_dashboard_settings"]

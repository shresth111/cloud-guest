"""SMALL-3: win-back action log + save rate for the Churn risk tab, behind
the CHURN-RISK flag ``ISP_REVENUE_HUB_ENABLED`` (off -> 404
``ISP_REVENUE_HUB_DISABLED``, like every /isp/revenue route).

* ``POST /isp/revenue/churn-risk/actions`` (``isp_billing.update``: owner /
  admin / billing, the roles that see the named churn list and act on it).
  Body ``subscriber_id`` resolves through IspScope: another ISP's or an
  out-of-confinement subscriber is a 404. Idempotent per ``idempotency_key``.
* ``GET /isp/revenue/churn-risk/save-rate?days=`` (``isp_billing.read``;
  counts only, no names).
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from . import revenue_logic as logic
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .revenue_router import RequireRevenueHubEnabled
from .winback_service import record_action, save_rate

winback_router = APIRouter(tags=["ISP Partner: revenue hub"])
_ON = [Depends(RequireRevenueHubEnabled)]


class WinbackActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    subscriber_id: uuid.UUID
    action: Literal["offer_renew", "ticket", "whatsapp_share"]
    reasons: list[str] = Field(default_factory=list, max_length=len(logic.RISK_REASONS))
    ref_id: uuid.UUID | None = None
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=64)


@winback_router.post(
    "/revenue/churn-risk/actions",
    status_code=201,
    dependencies=_ON + isp_guards("isp_billing.update"),
)
async def record_winback_action(
    request: Request,
    response: Response,
    payload: WinbackActionRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.domains.rbac.repository import RBACRepository

    from .plans_service import IspPlansService

    sub = await IspPlansService(session=db, audit=RBACRepository(db)).subscriber(
        isp, payload.subscriber_id
    )
    row, created = await record_action(
        db,
        isp,
        sub,
        action=payload.action,
        reasons=[r for r in payload.reasons if r in logic.RISK_REASONS],
        ref_id=payload.ref_id,
        idempotency_key=payload.idempotency_key,
    )
    if not created:
        response.status_code = 200
    return ok(
        request,
        {
            "id": str(row.id),
            "subscriber_id": str(row.subscriber_id),
            "action": row.action,
            "acted_at": row.acted_at.isoformat(),
            "window_ends_at": row.window_ends_at.isoformat(),
            "saved_at": row.saved_at.isoformat() if row.saved_at else None,
        },
        "Win-back action recorded",
    )


@winback_router.get(
    "/revenue/churn-risk/save-rate",
    dependencies=_ON + isp_guards("isp_billing.read"),
)
async def winback_save_rate(
    request: Request,
    days: int = Query(default=90, ge=7, le=365),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(request, await save_rate(db, isp, days=days), "Win-back save rate")


__all__ = ["winback_router"]

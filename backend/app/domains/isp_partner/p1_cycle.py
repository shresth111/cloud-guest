"""P1-2 API: ``GET /package-cycle-basis``, ``GET|PUT
/packages/{package_id}/cycle-basis``. Flag ``ISP_CYCLE_BASIS_ENABLED``
(default OFF -> 404). Keys ``isp_plans.read`` / ``isp_plans.update``. What the
basis does is in ``p1_cycle_hook``.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspFeatureDisabledError
from .http import ok
from .p1_config import get_p1_settings
from .p1_cycle_hook import package_basis
from .p1_models import IspPackageCycleBasis
from .plans_models import IspPackage
from .plans_service import IspPackageNotFoundError

__all__ = ["p1_cycle_router"]

PLANS_READ, PLANS_UPDATE = "isp_plans.read", "isp_plans.update"


async def RequireCycleBasisEnabled() -> None:
    if not get_p1_settings().cycle_basis_enabled:
        raise IspFeatureDisabledError()


p1_cycle_router = APIRouter(
    tags=["ISP Partner: billing cycle basis"],
    dependencies=[Depends(RequireCycleBasisEnabled)],
)


class CycleBasisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    basis: Literal["package", "subscriber"]


def basis_view(package_id: uuid.UUID, basis: str) -> dict:
    return {"package_id": str(package_id), "basis": basis}


async def _package(db: AsyncSession, isp: IspContext, package_id: uuid.UUID) -> Any:
    p = await db.get(IspPackage, package_id)
    if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
        raise IspPackageNotFoundError()
    return p


@p1_cycle_router.get("/package-cycle-basis", dependencies=isp_guards(PLANS_READ))
async def list_cycle_basis(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    rows = (
        await db.execute(
            select(IspPackageCycleBasis.package_id, IspPackageCycleBasis.basis).where(
                IspPackageCycleBasis.isp_organization_id == isp.isp_org_id,
                IspPackageCycleBasis.is_deleted.is_(False),
            )
        )
    ).all()
    return ok(
        request,
        {"items": [basis_view(r[0], r[1]) for r in rows]},
        "Billing cycle basis",
    )


@p1_cycle_router.get(
    "/packages/{package_id}/cycle-basis", dependencies=isp_guards(PLANS_READ)
)
async def get_cycle_basis(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    p = await _package(db, isp, package_id)
    return ok(
        request, basis_view(p.id, await package_basis(db, p.id)), "Billing cycle basis"
    )


@p1_cycle_router.put(
    "/packages/{package_id}/cycle-basis", dependencies=isp_guards(PLANS_UPDATE)
)
async def put_cycle_basis(
    request: Request,
    package_id: uuid.UUID,
    payload: CycleBasisRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    p = await _package(db, isp, package_id)
    row = (
        await db.execute(
            select(IspPackageCycleBasis).where(
                IspPackageCycleBasis.package_id == p.id,
                IspPackageCycleBasis.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspPackageCycleBasis(
            isp_organization_id=isp.isp_org_id, package_id=p.id, created_by=isp.user_id
        )
        db.add(row)
    row.basis = payload.basis
    row.updated_by = isp.user_id
    await db.flush()
    await db.commit()
    return ok(request, basis_view(p.id, row.basis), "Billing cycle basis saved")

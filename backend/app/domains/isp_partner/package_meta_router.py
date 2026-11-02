"""PKG-2: ``/isp/package-meta`` (package type + connection type).

Flag ``ISP_PACKAGE_META_ENABLED`` (default OFF -> 404). Keys: the existing
``isp_plans.read`` / ``isp_plans.update``. Labels only; no enforcement.

* ``GET /package-meta`` -> every package's labels for this ISP (the package
  list filters on it client-side; an ISP has tens of packages, not 10k).
* ``GET|PUT /package-meta/{package_id}``.
"""

from __future__ import annotations

import uuid
from functools import lru_cache
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspFeatureDisabledError
from .http import ok
from .package_meta_models import IspPackageMeta
from .plans_models import IspPackage
from .plans_service import IspPackageNotFoundError

__all__ = ["package_meta_router"]

PLANS_READ, PLANS_UPDATE = "isp_plans.read", "isp_plans.update"


class IspPackageMetaSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_PACKAGE_META_",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(default=False, description="ISP_PACKAGE_META_ENABLED")


@lru_cache(maxsize=1)
def get_package_meta_settings() -> IspPackageMetaSettings:
    return IspPackageMetaSettings()


async def RequirePackageMetaEnabled() -> None:
    if not get_package_meta_settings().enabled:
        raise IspFeatureDisabledError()


package_meta_router = APIRouter(
    prefix="/package-meta",
    tags=["ISP Partner: package labels"],
    dependencies=[Depends(RequirePackageMetaEnabled)],
)


class IspPackageMetaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package_type: Literal["home", "commercial", "sme", "enterprise"] | None = None
    connection_type: Literal["wireless", "fiber", "ethernet"] | None = None


def _view(package_id: uuid.UUID, row: IspPackageMeta | None) -> dict:
    return {
        "package_id": str(package_id),
        "package_type": row.package_type if row else None,
        "connection_type": row.connection_type if row else None,
    }


async def _package(
    db: AsyncSession, isp: IspContext, package_id: uuid.UUID
) -> IspPackage:
    p = await db.get(IspPackage, package_id)
    if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
        raise IspPackageNotFoundError()
    return p


async def _row(db: AsyncSession, package_id: uuid.UUID) -> IspPackageMeta | None:
    return (
        await db.execute(
            select(IspPackageMeta).where(
                IspPackageMeta.package_id == package_id,
                IspPackageMeta.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


@package_meta_router.get("", dependencies=isp_guards(PLANS_READ))
async def list_package_meta(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    rows = (
        (
            await db.execute(
                select(IspPackageMeta).where(
                    IspPackageMeta.isp_organization_id == isp.isp_org_id,
                    IspPackageMeta.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    return ok(request, {"items": [_view(r.package_id, r) for r in rows]}, "Labels")


@package_meta_router.get("/{package_id}", dependencies=isp_guards(PLANS_READ))
async def get_package_meta(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    p = await _package(db, isp, package_id)
    return ok(request, _view(p.id, await _row(db, p.id)), "Labels")


@package_meta_router.put("/{package_id}", dependencies=isp_guards(PLANS_UPDATE))
async def put_package_meta(
    request: Request,
    package_id: uuid.UUID,
    payload: IspPackageMetaRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    p = await _package(db, isp, package_id)
    row = await _row(db, p.id)
    if row is None:
        row = IspPackageMeta(
            id=uuid.uuid4(),
            isp_organization_id=isp.isp_org_id,
            package_id=p.id,
            created_by=isp.user_id,
        )
        db.add(row)
    row.package_type = payload.package_type
    row.connection_type = payload.connection_type
    row.updated_by = isp.user_id
    await db.flush()
    return ok(request, _view(p.id, row), "Labels saved")

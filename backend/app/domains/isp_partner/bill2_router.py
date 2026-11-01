"""BILL-2: ``GET|PUT /isp/zones/{zone_id}/branding`` (flag ISP_BILL2_ENABLED).

Keys: existing ``isp_zones.read`` / ``isp_zones.manage``. The GSTR-1 export
lives in ``billing_gst.gst_router``.
"""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .bill2_config import RequireBill2Enabled
from .bill2_models import IspZoneBranding
from .billing_extras import zone_branding_row
from .billing_models import IspZone
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import _err
from .http import ok

__all__ = ["bill2_router"]

ZONES_READ, ZONES_MANAGE = "isp_zones.read", "isp_zones.manage"
_IFSC = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
_VPA = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}$")

IspZoneNotFoundError = _err(
    "IspBill2ZoneNotFoundError", "ISP_ZONE_NOT_FOUND", 404, "Zone not found"
)

bill2_router = APIRouter(
    tags=["ISP Partner: invoice branding"],
    dependencies=[Depends(RequireBill2Enabled)],
)

_FIELDS = (
    "invoice_name",
    "bank_name",
    "bank_account_name",
    "bank_account_number",
    "bank_ifsc",
    "bank_branch",
    "upi_vpa",
)


class IspZoneBrandingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    invoice_name: str | None = Field(default=None, max_length=120)
    bank_name: str | None = Field(default=None, max_length=120)
    bank_account_name: str | None = Field(default=None, max_length=120)
    bank_account_number: str | None = Field(
        default=None, max_length=34, pattern=r"^[0-9A-Za-z]{6,34}$"
    )
    bank_ifsc: str | None = Field(default=None, max_length=11)
    bank_branch: str | None = Field(default=None, max_length=120)
    upi_vpa: str | None = Field(default=None, max_length=100)

    @field_validator("bank_ifsc")
    @classmethod
    def _ifsc(cls, v: str | None) -> str | None:
        if v and not _IFSC.match(v.upper()):
            raise ValueError("IFSC looks like ABCD0123456")
        return v.upper() if v else None

    @field_validator("upi_vpa")
    @classmethod
    def _vpa(cls, v: str | None) -> str | None:
        if v and not _VPA.match(v):
            raise ValueError("UPI id looks like name@bank")
        return v or None


def _view(zone_id: uuid.UUID, row: IspZoneBranding | None) -> dict:
    return {
        "zone_id": str(zone_id),
        **{f: getattr(row, f) if row else None for f in _FIELDS},
    }


async def _zone(db: AsyncSession, isp: IspContext, zone_id: uuid.UUID) -> IspZone:
    z = await db.get(IspZone, zone_id)
    if z is None or z.is_deleted or z.isp_organization_id != isp.isp_org_id:
        raise IspZoneNotFoundError()
    return z


@bill2_router.get("/zones/{zone_id}/branding", dependencies=isp_guards(ZONES_READ))
async def get_zone_branding(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    z = await _zone(db, isp, zone_id)
    return ok(
        request,
        _view(z.id, await zone_branding_row(db, isp.isp_org_id, z.id)),
        "Branding",
    )


@bill2_router.put("/zones/{zone_id}/branding", dependencies=isp_guards(ZONES_MANAGE))
async def put_zone_branding(
    request: Request,
    zone_id: uuid.UUID,
    payload: IspZoneBrandingRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    z = await _zone(db, isp, zone_id)
    row = await zone_branding_row(db, isp.isp_org_id, z.id)
    if row is None:
        row = IspZoneBranding(
            id=uuid.uuid4(),
            isp_organization_id=isp.isp_org_id,
            zone_id=z.id,
            created_by=isp.user_id,
        )
        db.add(row)
    data = payload.model_dump()
    for f in _FIELDS:
        setattr(row, f, data.get(f) or None)
    row.updated_by = isp.user_id
    await db.flush()
    return ok(request, _view(z.id, row), "Branding saved")

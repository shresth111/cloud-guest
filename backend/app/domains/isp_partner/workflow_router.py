"""RAKESH-FS: ``/isp/workflow`` (flag ``ISP_WORKFLOW_ENABLED``, default OFF).

* ``GET /workflow/features`` -- what the console may switch on (GB data
  limits, router zones, auto placement, franchisee logins).

Path ids are never named ``organization_id|customer_id|location_id|
router_id`` (the SCOPE_PARAM_ALIASES trap): ``device_ref``, ``zone_ref``,
``sub_ref``, ``user_ref``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .workflow_config import MB_PER_GB, RequireWorkflowEnabled, franchisee_logins_on

__all__ = ["workflow_router"]

PARTNER_READ = "isp_partner.read"

workflow_router = APIRouter(
    prefix="/workflow",
    tags=["ISP Partner: workflow"],
    dependencies=[Depends(RequireWorkflowEnabled)],
)


@workflow_router.get("/features", dependencies=isp_guards(PARTNER_READ))
async def workflow_features(
    request: Request, isp: IspContext = Depends(RequireIspPartner)
) -> dict:
    return ok(
        request,
        {
            "data_limit_unit": "GB",
            "mb_per_gb": MB_PER_GB,
            "router_zones": True,
            "auto_placement": True,
            "franchisee_logins": franchisee_logins_on(),
            "is_franchisee": isp.role_slug == "isp-franchisee",
        },
    )

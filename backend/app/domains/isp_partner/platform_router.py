"""``/platform/isp-partners`` -- Master endpoints (API_CONTRACT §3).

STUB on the BE branch. The FULLSTACK lane owns this file
(``feat/isp-partner-master-be``) and replaces it wholesale; it exists here
only so the E1 registration import in ``app/api/v1/router.py`` resolves.
No routes: with or without the flag, nothing is served from here yet.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .config import RequireIspFeatureEnabled

isp_partner_platform_router = APIRouter(
    prefix="/platform/isp-partners",
    tags=["ISP Partners (Master)"],
    dependencies=[Depends(RequireIspFeatureEnabled)],
)

__all__ = ["isp_partner_platform_router"]


# ADDENDUM_04 B6 §2 (PARITY-2): Master's per-ISP add-on allowance
# (``isp_addons.py``), GLOBAL-pinned on organizations.* like the routes above.
from .isp_addons import addon_platform_router  # noqa: E402

isp_partner_platform_router.include_router(addon_platform_router)

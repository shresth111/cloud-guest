"""Phase 2b PPPoE settings (ADDENDUM_02 §5, exception X2).

Its own ``BaseSettings`` so ``app/core/config.py`` is not edited. Everything
is OFF until ``ISP_PPPOE_ENABLED=true``. While off, the ISP PPPoE routes
answer 404 (on top of ``ISP_PARTNER_ENABLED``), the RADIUS authorize endpoint
answers Access-Reject, and the setup-script step is not offered.

``ISP_PPPOE_REST_SECRET`` is the shared secret FreeRADIUS sends (from
``mods-available/rest_isp_pppoe`` on the box only) in
``X-Wyfy-Pppoe-Rest-Secret``. The authorize reply carries the subscriber's
password (FreeRADIUS needs it to verify CHAP / MS-CHAPv2), so a NAS shared
secret alone must never be enough to call it: an ISP technician holds that
secret inside the router setup script. Empty secret = endpoint refuses all.
"""

from __future__ import annotations

from functools import lru_cache

from fastapi import HTTPException, status
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "IspPppoeSettings",
    "RequireIspPppoeEnabled",
    "get_isp_pppoe_settings",
]


class IspPppoeSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_PPPOE_",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(default=False, description="ISP_PPPOE_ENABLED")
    rest_secret: str = Field(
        default="",
        description=(
            "ISP_PPPOE_REST_SECRET: FreeRADIUS -> API header secret. Empty "
            "means the RADIUS endpoints refuse every request."
        ),
    )
    #: The X2 virtual server's ports on the hub (box-only file).
    auth_port: int = Field(default=1922)
    acct_port: int = Field(default=1923)
    #: RouterOS defaults written by the setup-script step; the ISP can
    #: override per router when generating.
    default_local_address: str = Field(default="100.64.0.1")
    default_pool_range: str = Field(default="100.64.0.10-100.64.3.254")
    default_pool_cidr: str = Field(default="100.64.0.0/22")
    interim_interval_seconds: int = Field(default=300, ge=60, le=3600)
    #: Session-Timeout cap so a subscriber's validity is re-checked at least
    #: this often even when it is far in the future.
    max_session_timeout_seconds: int = Field(default=86400, ge=600)


@lru_cache(maxsize=1)
def get_isp_pppoe_settings() -> IspPppoeSettings:
    return IspPppoeSettings()


async def RequireIspPppoeEnabled() -> None:
    """404 while ``ISP_PPPOE_ENABLED`` is off, before any auth runs."""
    if not get_isp_pppoe_settings().enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

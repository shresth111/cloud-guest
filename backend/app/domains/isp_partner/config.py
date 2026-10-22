"""ISP partner feature flag and settings (API_CONTRACT §0, §6.1).

Its own ``BaseSettings`` so ``app/core/config.py`` is not edited. The
variables are read without the ``CLOUDGUEST_`` prefix, exactly as the
contract names them: ``ISP_PARTNER_ENABLED`` and ``ISP_PARTNER_LOGIN_URL``.

``RequireIspFeatureEnabled`` is attached to every router of the feature at
router construction (``APIRouter(dependencies=[...])``), so it runs before
authentication. While the flag is off it raises a plain 404 -- the same body
FastAPI returns for a path that does not exist -- which makes the surface
indistinguishable from today's.
"""

from __future__ import annotations

from functools import lru_cache

from fastapi import HTTPException, status
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "IspPartnerSettings",
    "RequireIspFeatureEnabled",
    "get_isp_partner_settings",
]


class IspPartnerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_PARTNER_",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(
        default=False,
        description=(
            "ISP_PARTNER_ENABLED. Off by default: every /isp, "
            "/platform/isp-partners and TR-069 route answers 404."
        ),
    )
    login_url: str = Field(
        default="https://network.wyfyguest.com",
        description="ISP_PARTNER_LOGIN_URL, shown with a new ISP user's password.",
    )


@lru_cache(maxsize=1)
def get_isp_partner_settings() -> IspPartnerSettings:
    return IspPartnerSettings()


async def RequireIspFeatureEnabled() -> None:
    """404 while ``ISP_PARTNER_ENABLED`` is off, before any auth runs."""
    if not get_isp_partner_settings().enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

"""RAKESH-P1 flags. Every one defaults OFF; with a flag off the matching
routes answer 404 ``ISP_FEATURE_DISABLED`` and every hook is identity.

* ``ISP_TEMPLATE_RULES_ENABLED``: device count + MAC binding on speed
  templates (``/isp/speed-groups/{speed_group_id}/device-rules``).
* ``ISP_CYCLE_BASIS_ENABLED``: billing cycle linked to the subscriber's
  anchor day instead of the package validity (renewal end snaps).
* ``ISP_ZONE_COUPON_RIGHTS_ENABLED``: per-zone "may generate coupons" right
  for the franchisee role, inherited down the zone tree.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["IspP1Settings", "get_p1_settings"]


class IspP1Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    template_rules_enabled: bool = Field(
        default=False, description="ISP_TEMPLATE_RULES_ENABLED"
    )
    cycle_basis_enabled: bool = Field(
        default=False, description="ISP_CYCLE_BASIS_ENABLED"
    )
    zone_coupon_rights_enabled: bool = Field(
        default=False, description="ISP_ZONE_COUPON_RIGHTS_ENABLED"
    )


@lru_cache(maxsize=1)
def get_p1_settings() -> IspP1Settings:
    return IspP1Settings()

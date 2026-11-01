"""ZONE-1 feature flag. ``ISP_ZONES_ENABLED`` (default OFF): while off every
``/isp/zones/tree*`` route answers 404 ``ISP_ZONES_DISABLED`` and the
``scope_zone_id`` query parameter is ignored."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err


class IspZonesSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    zones_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_zones_settings() -> IspZonesSettings:
    return IspZonesSettings()


IspZonesDisabledError = _err(
    "IspZonesDisabledError", "ISP_ZONES_DISABLED", 404, "Not Found"
)
IspZoneCycleError = _err(
    "IspZoneCycleError",
    "ISP_ZONE_CYCLE",
    409,
    "A zone cannot be placed under itself or one of its own sub-zones",
)
IspZoneHasChildrenError = _err(
    "IspZoneHasChildrenError",
    "ISP_ZONE_HAS_CHILDREN",
    409,
    "Move or delete its sub-zones first",
)


async def RequireZonesEnabled() -> None:
    if not get_zones_settings().zones_enabled:
        raise IspZonesDisabledError()

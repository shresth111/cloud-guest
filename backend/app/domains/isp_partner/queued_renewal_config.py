"""QUEUED-RENEWAL feature flag. ``ISP_QUEUED_RENEWAL_ENABLED`` (default OFF):
every ``/isp/.../queued-renewals`` route answers 404
``ISP_QUEUED_RENEWAL_DISABLED`` and the activation pass does nothing."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err


class IspQueuedRenewalSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    queued_renewal_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_queued_renewal_settings() -> IspQueuedRenewalSettings:
    return IspQueuedRenewalSettings()


IspQueuedRenewalDisabledError = _err(
    "IspQueuedRenewalDisabledError", "ISP_QUEUED_RENEWAL_DISABLED", 404, "Not Found"
)
IspQueuedRenewalNotFoundError = _err(
    "IspQueuedRenewalNotFoundError",
    "ISP_QUEUED_RENEWAL_NOT_FOUND",
    404,
    "Queued renewal not found",
)
IspQueuedRenewalStateError = _err(
    "IspQueuedRenewalStateError",
    "ISP_QUEUED_RENEWAL_STATE",
    409,
    "This queued renewal cannot change now",
)


async def RequireQueuedRenewalEnabled() -> None:
    if not get_queued_renewal_settings().queued_renewal_enabled:
        raise IspQueuedRenewalDisabledError()

"""REFERRAL-1 feature flag and permission keys. ``ISP_REFERRALS_ENABLED``
(default OFF): every ``/isp/referrals`` route answers 404
``ISP_REFERRALS_DISABLED`` and the referral pass does nothing."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err

ISP_REFERRALS_READ = "isp_referrals.read"
#: record that subscriber A referred subscriber B; cancel a pending one
ISP_REFERRALS_CREATE = "isp_referrals.create"
#: per-ISP settings (reward amount, limits)
ISP_REFERRALS_MANAGE = "isp_referrals.manage"


class IspReferralsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    referrals_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_referrals_settings() -> IspReferralsSettings:
    return IspReferralsSettings()


IspReferralsDisabledError = _err(
    "IspReferralsDisabledError", "ISP_REFERRALS_DISABLED", 404, "Not Found"
)
IspReferralNotFoundError = _err(
    "IspReferralNotFoundError", "ISP_REFERRAL_NOT_FOUND", 404, "Referral not found"
)
IspReferralInvalidError = _err(
    "IspReferralInvalidError",
    "ISP_REFERRAL_INVALID",
    409,
    "This referral is not allowed",
)


async def RequireReferralsEnabled() -> None:
    if not get_referrals_settings().referrals_enabled:
        raise IspReferralsDisabledError()

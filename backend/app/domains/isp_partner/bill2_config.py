"""BILL-2 flag (ADDENDUM_06). ``ISP_BILL2_ENABLED`` default OFF.

While off: ``/isp/gst/*`` is a 404, invoice PDFs are rendered exactly as
before (no extras block, no zone branding), and a recharge/renew with
``cycles`` above 1 is refused (422), so nothing existing changes shape.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import IspFeatureDisabledError

__all__ = ["Bill2Settings", "RequireBill2Enabled", "get_bill2_settings"]

#: Most cycles one renewal may buy (12 x a 30-day package = a year).
MAX_CYCLES = 12


class Bill2Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_BILL2_", case_sensitive=False, extra="ignore"
    )

    enabled: bool = Field(default=False, description="ISP_BILL2_ENABLED")


@lru_cache(maxsize=1)
def get_bill2_settings() -> Bill2Settings:
    return Bill2Settings()


async def RequireBill2Enabled() -> None:
    if not get_bill2_settings().enabled:
        raise IspFeatureDisabledError()

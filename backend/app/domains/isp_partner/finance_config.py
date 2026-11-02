"""JAZE-4 feature flags. All default OFF; each answers a plain 404 while off
(same as ``RequireIspFeatureEnabled``), on top of ``ISP_PARTNER_ENABLED``.

* ``ISP_FINANCE_EXTRAS_ENABLED``: invoice template / bank details, product
  catalogue, package billing plan, static-IP leases, security deposits,
  billing contacts, invoice email, thermal slips.
* ``ISP_ZONE_LEDGER_ENABLED``: the labels-only zone ledger and the TDS 194H
  statement data (pending founder confirmation).
* ``ISP_WHATSAPP_AUTOMATION_ENABLED``: automated WhatsApp through the ISP's
  own Meta sender, the public pay-link page, and the sweeps.
* ``ISP_TELEGRAM_ALERTS_ENABLED``: router/AP DOWN/UP alerts to the ISP's own
  Telegram bot.
"""

from __future__ import annotations

from functools import lru_cache

from fastapi import HTTPException
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import IspFeatureDisabledError


class IspFinanceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    finance_extras_enabled: bool = Field(default=False)
    zone_ledger_enabled: bool = Field(default=False)
    whatsapp_automation_enabled: bool = Field(default=False)
    telegram_alerts_enabled: bool = Field(default=False)
    #: Base URL the pay link points at (the partner host).
    pay_link_base_url: str = Field(default="https://network.wyfyguest.com")


@lru_cache(maxsize=1)
def get_finance_settings() -> IspFinanceSettings:
    return IspFinanceSettings()


def _off() -> HTTPException:
    # ERROR-COPY: same 404 "Not Found", now with data.code.
    return IspFeatureDisabledError()


async def RequireFinanceExtras() -> None:
    if not get_finance_settings().finance_extras_enabled:
        raise _off()


async def RequireZoneLedger() -> None:
    if not get_finance_settings().zone_ledger_enabled:
        raise _off()


async def RequireWhatsappAutomation() -> None:
    if not get_finance_settings().whatsapp_automation_enabled:
        raise _off()


async def RequireTelegramAlerts() -> None:
    if not get_finance_settings().telegram_alerts_enabled:
        raise _off()

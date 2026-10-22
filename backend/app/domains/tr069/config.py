"""TR-069 settings (API_CONTRACT §6.1): env prefix ``TR069_``, its own
``BaseSettings`` so ``core/config.py`` is not edited."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import Tr069NotEnabledError


class Tr069Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="TR069_", case_sensitive=False, extra="ignore"
    )

    enabled: bool = Field(default=False, description="TR069_ENABLED")
    nbi_url: str = Field(default="http://genieacs-nbi:7557")
    acs_public_url: str = Field(default="https://acs-staging.wyfyguest.com/")
    edge_shared_secret: str = Field(default="")
    sync_min_interval_s: int = Field(default=30, ge=0)
    nbi_timeout_s: float = Field(default=10.0, gt=0)


@lru_cache(maxsize=1)
def get_tr069_settings() -> Tr069Settings:
    return Tr069Settings()


async def RequireTr069Enabled() -> None:
    """503 ``TR069_NOT_ENABLED`` on ``/isp/tr069/*`` while TR069_ENABLED is
    off. (``ISP_PARTNER_ENABLED`` is checked first by the router's own flag
    dependency, so with both off the answer is still a plain 404.)"""
    if not get_tr069_settings().enabled:
        raise Tr069NotEnabledError()

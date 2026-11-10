"""RAKESH-FS: the ISP workflow flag (Zone -> Router -> Subscriber -> Package).

``ISP_WORKFLOW_ENABLED`` (default OFF). While off:

* ``/isp/workflow/*`` answers 404 ``ISP_FEATURE_DISABLED`` (the console then
  keeps every old form exactly as it was, e.g. data limits in MB);
* the ``isp-franchisee`` role cannot be granted and a user holding it gets
  ``ISP_ROLE_REQUIRED`` on every ``/isp`` request (never a wider view).

Franchisee logins additionally need ``ISP_ZONES_ENABLED`` (the ZONE-1 subtree
rules are what confine them).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import IspFeatureDisabledError

#: DECISIONS-1 (2026-11-10): 1 GB = 1000 MB in the ISP console. Telecom
#: plans in India are sold in decimal GB ("3,000 GB", not 3,072,000 MB).
#: The DB still stores whole MB; enforcement still treats 1 MB as 2**20
#: bytes (enforcement.MB), so a "3000 GB" cap is 3,000,000 stored MB.
MB_PER_GB = 1000


class IspWorkflowSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_WORKFLOW_",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(default=False, description="ISP_WORKFLOW_ENABLED")


@lru_cache(maxsize=1)
def get_workflow_settings() -> IspWorkflowSettings:
    return IspWorkflowSettings()


async def RequireWorkflowEnabled() -> None:
    if not get_workflow_settings().enabled:
        raise IspFeatureDisabledError()


def franchisee_logins_on() -> bool:
    from .zones_config import get_zones_settings

    return get_workflow_settings().enabled and get_zones_settings().zones_enabled


def mb_to_gb(mb: int | None) -> float | None:
    """Stored MB -> GB for display, 3 decimals (never rounds a value to 0)."""
    if mb is None:
        return None
    return round(mb / MB_PER_GB, 3)


def gb_to_mb(gb: float | None) -> int | None:
    """Entered GB -> stored whole MB (nearest; at least 1 for any positive)."""
    if gb is None:
        return None
    if gb < 0:
        raise ValueError("data limit cannot be negative")
    mb = round(gb * MB_PER_GB)
    return max(mb, 1) if gb > 0 else 0

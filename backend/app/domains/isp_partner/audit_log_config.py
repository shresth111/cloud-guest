"""AUDIT-LOG feature flag and keys. ``ISP_AUDIT_LOG_ENABLED`` (default OFF):
``/isp/audit-log`` answers 404 ``ISP_AUDIT_LOG_DISABLED`` and no IP is
captured on audit rows."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err

ISP_AUDIT_READ = "isp_audit.read"
ISP_AUDIT_EXPORT = "isp_audit.export"


class IspAuditLogSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    audit_log_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_audit_log_settings() -> IspAuditLogSettings:
    return IspAuditLogSettings()


IspAuditLogDisabledError = _err(
    "IspAuditLogDisabledError", "ISP_AUDIT_LOG_DISABLED", 404, "Not Found"
)


async def RequireAuditLogEnabled() -> None:
    if not get_audit_log_settings().audit_log_enabled:
        raise IspAuditLogDisabledError()

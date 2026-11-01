"""INCIDENTS-1 feature flag and permission keys.

``ISP_INCIDENTS_ENABLED`` (default OFF): while off every ``/isp/incidents``
route answers 404 ``ISP_INCIDENTS_DISABLED``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err

ISP_INCIDENTS_READ = "isp_incidents.read"
#: open an incident, move its status, add notes, refresh the affected list
ISP_INCIDENTS_MANAGE = "isp_incidents.manage"
#: broadcast to the affected subscribers; bulk grace (which also needs
#: isp_subscribers.update, the JAZE-1 grace key)
ISP_INCIDENTS_EXECUTE = "isp_incidents.execute"
#: the affected-subscriber CSV (names + phones)
ISP_INCIDENTS_EXPORT = "isp_incidents.export"


class IspIncidentsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    incidents_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_incidents_settings() -> IspIncidentsSettings:
    return IspIncidentsSettings()


IspIncidentsDisabledError = _err(
    "IspIncidentsDisabledError", "ISP_INCIDENTS_DISABLED", 404, "Not Found"
)
IspIncidentNotFoundError = _err(
    "IspIncidentNotFoundError", "ISP_INCIDENT_NOT_FOUND", 404, "Incident not found"
)
IspIncidentStateError = _err(
    "IspIncidentStateError",
    "ISP_INCIDENT_STATE",
    409,
    "That step does not fit the incident's current status",
)


async def RequireIncidentsEnabled() -> None:
    if not get_incidents_settings().incidents_enabled:
        raise IspIncidentsDisabledError()

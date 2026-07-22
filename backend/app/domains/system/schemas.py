from __future__ import annotations

from pydantic import BaseModel


class DependencyStatus(BaseModel):
    name: str
    status: str  # healthy, degraded, down
    latency_ms: float | None = None


class SystemHealthResponse(BaseModel):
    status: str  # healthy, degraded, down
    version: str
    uptime_seconds: float
    dependencies: list[DependencyStatus]


class SystemStatusResponse(BaseModel):
    status: str
    version: str
    environment: str
    uptime_seconds: float
    active_organizations: int = 0
    active_locations: int = 0
    online_routers: int = 0
    active_guests: int = 0
    total_users: int = 0


class SystemVersionResponse(BaseModel):
    version: str
    build: str | None = None
    commit: str | None = None
    python_version: str
    api_version: str = "v1"

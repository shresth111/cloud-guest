from pydantic import BaseModel, Field


class LivenessData(BaseModel):
    service: str
    environment: str
    uptime_seconds: float = Field(ge=0)


class DependencyStatus(BaseModel):
    status: str
    latency_ms: float | None = Field(default=None, ge=0)
    error: str | None = None


class ReadinessData(BaseModel):
    service: str
    database: DependencyStatus
    redis: DependencyStatus


"""Pydantic schemas for the Monitoring domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class RouterMetricBase(BaseModel):
    cpu_usage: float = Field(ge=0.0, le=100.0)
    memory_usage: float = Field(ge=0.0, le=100.0)
    disk_usage: float = Field(ge=0.0, le=100.0)
    temperature: float | None = None
    voltage: float | None = None
    uptime: int = Field(ge=0)
    rx_throughput: float = Field(default=0.0)
    tx_throughput: float = Field(default=0.0)
    bandwidth: float = Field(default=0.0)
    latency: float = Field(default=0.0)
    packet_loss: float = Field(default=0.0, ge=0.0, le=100.0)
    jitter: float = Field(default=0.0)
    connected_clients: int = Field(default=0, ge=0)
    freeradius_status: str = Field(default="up")
    interface_status: dict[str, Any] = Field(default_factory=dict)
    wireguard_tunnel_status: dict[str, Any] = Field(default_factory=dict)

class RouterMetricCreate(RouterMetricBase):
    router_id: uuid.UUID

class RouterMetricResponse(RouterMetricBase):
    id: uuid.UUID
    router_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class SystemHealthResponse(BaseModel):
    component: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class HealthOverviewResponse(BaseModel):
    status: str
    database: str
    redis: str
    celery: str
    api: str
    freeradius: str
    components: list[SystemHealthResponse]

class MonitoringOverviewResponse(BaseModel):
    total_organizations: int
    total_locations: int
    routers_online: int
    routers_offline: int
    active_guest_sessions: int
    today_guests: int
    alerts_active: int
    system_status: str

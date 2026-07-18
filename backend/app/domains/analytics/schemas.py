"""Pydantic schemas for the Analytics domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class DashboardKPIsResponse(BaseModel):
    total_organizations: int
    total_locations: int
    routers_online: int
    routers_offline: int
    active_guest_sessions: int
    today_guests: int
    peak_concurrent_users: int
    total_bandwidth_gb: float
    average_session_duration_mins: float
    otp_success_rate: float
    voucher_usage: int
    top_routers: list[dict[str, Any]] = Field(default_factory=list)
    top_locations: list[dict[str, Any]] = Field(default_factory=list)

class AnalyticsAggregateResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    metric_name: str
    metric_value: float
    dimensions: dict[str, Any]
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class PlatformAnalyticsResponse(BaseModel):
    total_traffic_bytes: int
    active_users: int
    system_load: float
    timestamp: datetime

class OrganizationAnalyticsResponse(BaseModel):
    organization_id: uuid.UUID
    total_users: int
    active_connections: int
    data_consumed_mb: float

class LocationAnalyticsResponse(BaseModel):
    location_id: uuid.UUID
    active_guests: int
    peak_guests: int
    bandwidth_used_gb: float

class RouterAnalyticsResponse(BaseModel):
    router_id: uuid.UUID
    uptime_percentage: float
    avg_cpu: float
    avg_memory: float
    tx_bytes: int
    rx_bytes: int

class GuestAnalyticsResponse(BaseModel):
    total_guests: int
    new_guests: int
    returning_guests: int
    auth_methods: dict[str, int] = Field(default_factory=dict)

class VoucherAnalyticsResponse(BaseModel):
    total_generated: int
    total_redeemed: int
    revenue_amount: float
    currency: str = "USD"

class OTPAnalyticsResponse(BaseModel):
    total_sent: int
    total_verified: int
    success_rate: float

"""Pydantic request/response schemas for the Subscription domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

class PlanLimits(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    organizations: int
    locations: int
    routers: int
    users: int
    guest_sessions: int
    api_requests: int
    captive_portals: int
    reports: bool
    storage_gb: int
    retention_days: int

class SubscriptionPlanCreate(BaseModel):
    name: str = Field(..., max_length=100)
    code: str = Field(..., max_length=50)
    description: str | None = None
    price_monthly: float = Field(0.0, ge=0)
    price_yearly: float = Field(0.0, ge=0)
    currency: str = Field("USD", min_length=3, max_length=3)
    trial_days: int = Field(0, ge=0)
    limits: PlanLimits

class SubscriptionPlanUpdate(BaseModel):
    name: str | None = Field(None, max_length=100)
    description: str | None = None
    price_monthly: float | None = Field(None, ge=0)
    price_yearly: float | None = Field(None, ge=0)
    is_active: bool | None = None
    trial_days: int | None = Field(None, ge=0)
    limits: PlanLimits | None = None

class SubscriptionPlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    code: str
    description: str | None
    price_monthly: float
    price_yearly: float
    currency: str
    is_active: bool
    trial_days: int
    limits: dict[str, Any]
    created_at: datetime
    updated_at: datetime

class SubscriptionCreate(BaseModel):
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    billing_cycle: str = Field("monthly", pattern="^(monthly|yearly)$")
    auto_renew: bool = True

class SubscriptionChangePlan(BaseModel):
    new_plan_id: uuid.UUID
    reason: str | None = None

class SubscriptionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    plan: SubscriptionPlanResponse
    status: str
    billing_cycle: str
    current_period_start: datetime
    current_period_end: datetime
    trial_start: datetime | None
    trial_end: datetime | None
    auto_renew: bool
    cancel_at_period_end: bool
    canceled_at: datetime | None
    suspended_at: datetime | None
    ended_at: datetime | None
    grace_period_end: datetime | None
    created_at: datetime
    updated_at: datetime

class PlanChangeHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    old_plan_id: uuid.UUID | None
    new_plan_id: uuid.UUID
    changed_by_user_id: uuid.UUID | None
    reason: str | None
    created_at: datetime

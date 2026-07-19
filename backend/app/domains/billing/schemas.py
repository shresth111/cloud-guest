"""Pydantic request/response schemas for the Billing API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py``.

Money (``Plan.base_price``) and usage (``UsageMetric.value``,
``PlanFeature.limit_value``) fields are typed ``Decimal`` throughout, never
``float`` -- pydantic v2 serializes ``Decimal`` to a JSON string by default
(``model_dump(mode="json")``), preserving exact precision end to end.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from .constants import (
    BillingCycle,
    LicenseChangeType,
    LicenseStatus,
    PlanFeatureKey,
    PlanFeatureType,
    PlanType,
    UsageMetricKey,
)

__all__ = [
    "PlanFeatureCreateRequest",
    "PlanCreateRequest",
    "PlanUpdateRequest",
    "PlanFeatureResponse",
    "PlanResponse",
    "PlanListResponse",
    "LicenseAssignRequest",
    "LicenseSuspendRequest",
    "LicenseUpgradeRequest",
    "LicenseDowngradeRequest",
    "LicenseChangeLogResponse",
    "LicenseResponse",
    "UsageMetricResponse",
    "UsageLimitCheckResponse",
    "UsageSummaryResponse",
]


# ============================================================================
# Plan / PlanFeature
# ============================================================================


class PlanFeatureCreateRequest(BaseModel):
    feature_key: PlanFeatureKey
    feature_type: PlanFeatureType
    limit_value: Decimal | None = Field(default=None, ge=0)
    is_enabled: bool | None = None
    tier_value: str | None = None


class PlanCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    slug: str = Field(..., min_length=2, max_length=150)
    plan_type: PlanType
    description: str | None = Field(default=None, max_length=2000)
    billing_cycle: BillingCycle = BillingCycle.MONTHLY
    base_price: Decimal = Field(..., ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    is_active: bool = True
    is_public: bool = True
    sort_order: int = 0
    features: list[PlanFeatureCreateRequest] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Professional",
                "slug": "professional",
                "plan_type": "professional",
                "description": "For growing multi-location deployments.",
                "billing_cycle": "monthly",
                "base_price": "199.00",
                "currency": "USD",
                "is_active": True,
                "is_public": True,
                "sort_order": 3,
                "features": [
                    {
                        "feature_key": "max_locations",
                        "feature_type": "limit",
                        "limit_value": "10",
                    },
                    {
                        "feature_key": "white_label",
                        "feature_type": "boolean",
                        "is_enabled": True,
                    },
                ],
            }
        }
    )


class PlanUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    billing_cycle: BillingCycle | None = None
    base_price: Decimal | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    is_active: bool | None = None
    is_public: bool | None = None
    sort_order: int | None = None
    features: list[PlanFeatureCreateRequest] | None = Field(
        default=None,
        description=(
            "When provided, fully replaces this plan's feature set "
            "(existing rows are deleted and these are inserted)."
        ),
    )


class PlanFeatureResponse(BaseModel):
    id: str
    feature_key: str
    feature_type: str
    limit_value: Decimal | None
    is_enabled: bool | None
    tier_value: str | None

    model_config = ConfigDict(from_attributes=True)


class PlanResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan_type: str
    description: str | None
    billing_cycle: str
    base_price: Decimal
    currency: str
    is_active: bool
    is_public: bool
    created_by_user_id: str | None
    sort_order: int
    features: list[PlanFeatureResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlanListResponse(BaseModel):
    items: list[PlanResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# License
# ============================================================================


class LicenseAssignRequest(BaseModel):
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    expires_at: datetime | None = None


class LicenseSuspendRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class LicenseUpgradeRequest(BaseModel):
    new_plan_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=500)


class LicenseDowngradeRequest(BaseModel):
    new_plan_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=500)


class LicenseChangeLogResponse(BaseModel):
    id: str
    from_plan_id: str | None
    to_plan_id: str
    change_type: LicenseChangeType
    changed_at: datetime
    changed_by_user_id: str | None
    reason: str | None

    model_config = ConfigDict(from_attributes=True)


class LicenseResponse(BaseModel):
    id: str
    organization_id: str
    plan_id: str
    status: LicenseStatus
    activated_at: datetime | None
    expires_at: datetime | None
    suspended_at: datetime | None
    suspended_reason: str | None
    cancelled_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Usage
# ============================================================================


class UsageMetricResponse(BaseModel):
    metric_key: UsageMetricKey
    period_start: datetime
    period_end: datetime
    value: Decimal
    recorded_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UsageLimitCheckResponse(BaseModel):
    metric_key: UsageMetricKey
    current_value: Decimal
    limit_value: Decimal
    exceeded: bool


class UsageSummaryResponse(BaseModel):
    organization_id: str
    metrics: list[UsageMetricResponse]
    limit_checks: list[UsageLimitCheckResponse]
    any_limit_exceeded: bool

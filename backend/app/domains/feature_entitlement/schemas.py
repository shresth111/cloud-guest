from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FeatureInfo(BaseModel):
    key: str
    name: str
    description: str | None = None
    category: str = "general"
    type: str = "boolean"  # boolean, limit, tier
    default_enabled: bool = False
    limits: dict[str, Any] = Field(default_factory=dict)
    # Populated only for ``type == "tier"`` (today, exactly
    # ``support_level`` -- see ``app.domains.billing.constants
    # .TIER_FEATURE_KEYS``) -- the closed set of legal ``tier_value``
    # strings a caller may pick for this feature (mirrors
    # ``SupportTier``'s own members), plus the tier a Plan without an
    # explicit override effectively carries. A ``"boolean"``/``"limit"``
    # feature leaves both fields at their empty/``None`` default -- a
    # tier-typed feature is never legally boolean-toggled (see
    # ``FeatureEntitlementService.list_features``'s own docstring for why
    # this exists: a TIER-typed feature rendered as a plain on/off toggle
    # is exactly what let the Smart Location Provisioning wizard send a
    # ``support_level`` override with no ``tier_value``, which
    # ``validate_feature_value`` correctly rejects).
    tier_options: list[str] = Field(default_factory=list)
    default_tier_value: str | None = None


class FeatureListResponse(BaseModel):
    features: list[FeatureInfo]


class CustomerFeatureValue(BaseModel):
    feature_key: str
    enabled: bool
    limits: dict[str, Any] = Field(default_factory=dict)


class CustomerFeaturesResponse(BaseModel):
    customer_id: str
    features: list[CustomerFeatureValue]


class CustomerFeaturesUpdateRequest(BaseModel):
    features: list[CustomerFeatureValue]


class CustomerFeaturesUpdateResponse(BaseModel):
    customer_id: str
    features: list[CustomerFeatureValue]
    message: str = "Features updated"

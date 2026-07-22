from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FeatureInfo(BaseModel):
    key: str
    name: str
    description: str | None = None
    category: str = "general"
    type: str = "boolean"  # boolean, limit
    default_enabled: bool = False
    limits: dict[str, Any] = Field(default_factory=dict)


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

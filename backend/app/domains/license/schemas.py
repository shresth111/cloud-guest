"""Pydantic schemas for the License domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class LicenseGenerateRequest(BaseModel):
    organization_id: uuid.UUID
    tier: str = Field("starter", max_length=50)
    duration_days: int = Field(365, ge=1)


class LicenseActivateRequest(BaseModel):
    license_key: str = Field(..., min_length=16, max_length=100)
    router_id: uuid.UUID


class LicenseValidateRequest(BaseModel):
    license_key: str = Field(..., min_length=16, max_length=100)
    router_id: uuid.UUID
    organization_id: uuid.UUID


class LicenseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    router_id: uuid.UUID | None
    license_key: str
    status: str
    tier: str
    issued_at: datetime
    activated_at: datetime | None
    expires_at: datetime | None
    deallocated_at: datetime | None
    last_validated_at: datetime | None
    created_at: datetime
    updated_at: datetime

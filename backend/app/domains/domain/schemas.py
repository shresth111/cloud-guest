"""Pydantic schemas for the Custom Domains domain."""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class CustomDomainCreate(BaseModel):
    organization_id: uuid.UUID
    domain_name: str = Field(..., pattern=r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$")


class CustomDomainResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    domain_name: str
    verification_token: str
    is_verified: bool
    dns_validation_status: str
    ssl_status: str
    ssl_configured_at: datetime | None
    created_at: datetime
    updated_at: datetime

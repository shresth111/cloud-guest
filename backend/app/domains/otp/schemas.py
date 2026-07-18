"""Pydantic request/response schemas for the OTP API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py`` -- see
``service.py``'s module docstring for why this module's guest-facing
endpoints use that envelope, unlike ``app.domains.wireguard``/
``app.domains.router_agent``'s device-facing ones.

No response schema here ever includes ``code_hash`` or the plaintext code
itself -- the code is only ever "sent" through ``SmsProviderProtocol``/
``EmailProviderProtocol`` (see ``service.py``), never returned in any API
response.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .constants import OtpChannel, OtpPurpose

__all__ = [
    "OtpRequestCreate",
    "OtpVerifyRequest",
    "OtpRequestResponse",
    "OtpVerifyResponse",
    "OtpRequestAdminResponse",
    "OtpRequestListResponse",
]


# ============================================================================
# Request schemas
# ============================================================================


class OtpRequestCreate(BaseModel):
    identifier: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Phone number (SMS) or email address (EMAIL) to send the code to.",
    )
    channel: OtpChannel
    purpose: OtpPurpose = OtpPurpose.GUEST_LOGIN
    organization_id: uuid.UUID | None = Field(
        default=None,
        description="Tenant the requesting captive portal belongs to, if known.",
    )
    location_id: uuid.UUID | None = Field(
        default=None,
        description="Location the requesting captive portal belongs to, if known.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "identifier": "+15551234567",
                "channel": "sms",
                "purpose": "guest_login",
                "organization_id": None,
                "location_id": None,
            }
        }
    )


class OtpVerifyRequest(BaseModel):
    identifier: str = Field(..., min_length=3, max_length=255)
    code: str = Field(..., min_length=4, max_length=10)
    purpose: OtpPurpose = OtpPurpose.GUEST_LOGIN

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "identifier": "+15551234567",
                "code": "042817",
                "purpose": "guest_login",
            }
        }
    )


# ============================================================================
# Response schemas
# ============================================================================


class OtpRequestResponse(BaseModel):
    """Returned by ``POST /otp/request`` -- never includes the code itself,
    only enough for the captive-portal frontend to know a code was issued
    and when it expires."""

    id: str
    identifier: str
    channel: OtpChannel
    purpose: OtpPurpose
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OtpVerifyResponse(BaseModel):
    """Returned by ``POST /otp/verify`` on success -- a failed verification
    never reaches this schema, it raises one of ``exceptions.py``'s distinct
    ``OtpError`` subclasses instead (see that module's docstring)."""

    id: str
    identifier: str
    purpose: OtpPurpose
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OtpRequestAdminResponse(BaseModel):
    """Admin/support-facing view (``GET /otp/requests``) -- includes
    lifecycle/audit-relevant fields no guest-facing response exposes
    (``attempt_count``, ``is_consumed``), but never ``code_hash``."""

    id: str
    identifier: str
    channel: OtpChannel
    purpose: OtpPurpose
    expires_at: datetime
    verified_at: datetime | None
    attempt_count: int
    max_attempts: int
    is_consumed: bool
    organization_id: str | None
    location_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OtpRequestListResponse(BaseModel):
    items: list[OtpRequestAdminResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

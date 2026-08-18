"""Pydantic request/response schemas for the Channel Partner API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions --
see ``app.domains.quotation.schemas``) and is wrapped in the project's
standard ``ApiResponse``/``build_response`` envelope by ``router.py``.

GSTIN and Indian-mobile validation are both new to this codebase -- see
this module's own field validators below and
``docs/channel-partner-onboarding-spec.md`` Key Finding 5 for why neither
format was ever validated anywhere else in this backend before now.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# India's GSTIN is always exactly 15 characters:
# [state code:2][PAN:10][entity code:1][default "Z":1][checksum:1].
GSTIN_PATTERN = re.compile(r"^\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]{1}$")

# Accepts "9876543210", "+919876543210", "919876543210" -- normalizes to
# "+919876543210" before storage, so the stored value is always
# Twilio-ready with no send-time reformatting.
INDIAN_MOBILE_PATTERN = re.compile(r"^(?:\+?91)?([6-9]\d{9})$")

__all__ = [
    "GSTIN_PATTERN",
    "INDIAN_MOBILE_PATTERN",
    "normalize_indian_phone",
    "normalize_gst_number",
    "ChannelPartnerCreateRequest",
    "ChannelPartnerResponse",
    "ChannelPartnerListResponse",
]


def normalize_indian_phone(value: str) -> str:
    """Shared normalizer -- used by both the schema's own field validator
    and any service-layer caller that needs to re-validate a value that
    didn't pass through the schema (there are none today, but this keeps
    the one real implementation in one place rather than duplicating the
    regex)."""
    match = INDIAN_MOBILE_PATTERN.match(value.strip())
    if not match:
        raise ValueError(
            "Enter a valid 10-digit Indian mobile number, e.g. 9876543210."
        )
    return f"+91{match.group(1)}"


def normalize_gst_number(value: str) -> str:
    normalized = value.strip().upper()
    if not GSTIN_PATTERN.match(normalized):
        raise ValueError("Enter a valid 15-character GSTIN, e.g. 27AAAAA0000A1Z5.")
    return normalized


# ============================================================================
# Request schemas
# ============================================================================


class ChannelPartnerCreateRequest(BaseModel):
    """The Master console's "Onboard Partner" form submission -- create +
    onboard + trigger the welcome message, all in one request."""

    name: str = Field(..., min_length=2, max_length=255)
    phone: str = Field(..., description="10-digit Indian mobile number.")
    email: EmailStr | None = Field(
        default=None,
        description=(
            "Optional. When provided, a branded welcome email is sent in "
            "addition to the welcome SMS."
        ),
    )
    address: str = Field(..., min_length=5, max_length=2_000)
    city: str = Field(..., min_length=1, max_length=100)
    gst_number: str = Field(..., min_length=15, max_length=15)

    @field_validator("phone")
    @classmethod
    def validate_and_normalize_phone(cls, value: str) -> str:
        return normalize_indian_phone(value)

    @field_validator("gst_number")
    @classmethod
    def validate_gst_number(cls, value: str) -> str:
        return normalize_gst_number(value)


# ============================================================================
# Response schemas
# ============================================================================


class ChannelPartnerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    phone: str
    email: str | None
    address: str
    city: str
    gst_number: str
    status: str
    welcome_sms_sent_at: datetime | None
    welcome_sms_error: str | None
    welcome_email_sent_at: datetime | None
    welcome_email_error: str | None
    created_at: datetime
    updated_at: datetime


class ChannelPartnerListResponse(BaseModel):
    items: list[ChannelPartnerResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

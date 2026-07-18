"""Pydantic request/response schemas for the Voucher API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py`` -- except
``GET .../export``, which deliberately returns raw ``text/csv``, not JSON
(see ``service.py``'s module docstring for why).

Admin response schemas (``VoucherResponse``, ``VoucherBatchResponse``)
include the voucher's plaintext ``code`` -- see ``models.py``'s module
docstring for why storing/displaying it in plaintext is this module's
deliberate design, unlike OTP's ``code_hash``-only responses.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "VoucherBatchCreate",
    "VoucherBatchRevokeRequest",
    "VoucherImportRequest",
    "VoucherValidateRequest",
    "VoucherRedeemRequest",
    "VoucherBatchResponse",
    "VoucherBatchListResponse",
    "VoucherResponse",
    "VoucherListResponse",
    "VoucherBatchStatsResponse",
    "VoucherImportResponse",
    "VoucherValidateResponse",
    "VoucherRedeemResponse",
]


# ============================================================================
# Request schemas
# ============================================================================


class VoucherBatchCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = None
    quantity: int = Field(
        ...,
        ge=0,
        le=1000,
        description=(
            "How many vouchers to platform-generate for this batch. 0 is "
            "legal -- a batch created purely as an import target for "
            "pre-printed codes (see POST /vouchers/import)."
        ),
    )
    code_length: int = Field(default=8, ge=4, le=20)
    code_prefix: str | None = Field(default=None, max_length=20)
    validity_minutes: int = Field(
        ...,
        ge=1,
        description=(
            "How long a voucher grants access once redeemed "
            "(not the batch's own shelf-life)."
        ),
    )
    batch_expires_at: datetime | None = Field(
        default=None,
        description="Codes not redeemed by this timestamp become permanently invalid.",
    )
    max_uses_per_voucher: int = Field(default=1, ge=1)
    data_limit_mb: int | None = Field(default=None, ge=0)
    notes: str | None = Field(default=None, max_length=2000)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Lobby Front Desk - July",
                "organization_id": "00000000-0000-0000-0000-000000000000",
                "location_id": None,
                "quantity": 100,
                "code_length": 8,
                "code_prefix": "JULY-",
                "validity_minutes": 1440,
                "batch_expires_at": None,
                "max_uses_per_voucher": 1,
                "data_limit_mb": None,
                "notes": None,
            }
        }
    )


class VoucherBatchRevokeRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class VoucherImportRequest(BaseModel):
    batch_id: uuid.UUID = Field(
        ..., description="The existing batch to import pre-printed codes into."
    )
    codes: list[str] = Field(..., min_length=1, max_length=1000)


class VoucherValidateRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=64)

    model_config = ConfigDict(json_schema_extra={"example": {"code": "JULY-XK7P9Q2M"}})


class VoucherRedeemRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=64)
    identifier: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="The guest's self-reported identifier (phone/email/device-MAC).",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"code": "JULY-XK7P9Q2M", "identifier": "+15551234567"}
        }
    )


# ============================================================================
# Response schemas
# ============================================================================


class VoucherBatchResponse(BaseModel):
    id: str
    name: str
    organization_id: str
    location_id: str | None
    quantity: int
    code_length: int
    code_prefix: str | None
    validity_minutes: int
    batch_expires_at: datetime | None
    max_uses_per_voucher: int
    data_limit_mb: int | None
    status: str
    created_by_user_id: str | None
    approved_by_user_id: str | None
    approved_at: datetime | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VoucherBatchListResponse(BaseModel):
    items: list[VoucherBatchResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class VoucherResponse(BaseModel):
    id: str
    batch_id: str
    code: str
    status: str
    use_count: int
    redeemed_at: datetime | None
    last_used_at: datetime | None
    redeemed_identifier: str | None
    expires_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VoucherListResponse(BaseModel):
    items: list[VoucherResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class VoucherBatchStatsResponse(BaseModel):
    batch_id: str
    total: int
    unused: int
    active: int
    exhausted: int
    expired: int
    revoked: int
    redemption_rate: float


class VoucherImportRejection(BaseModel):
    code: str
    reason: str


class VoucherImportResponse(BaseModel):
    imported_count: int
    imported_codes: list[str]
    rejected: list[VoucherImportRejection]


class VoucherValidateResponse(BaseModel):
    """Returned by ``POST /vouchers/validate`` on success -- a failed
    validation never reaches this schema, it raises one of ``exceptions.py``'s
    distinct ``VoucherError`` subclasses instead."""

    code: str
    is_first_use: bool
    uses_remaining: int
    max_uses_per_voucher: int
    expires_at: datetime | None
    batch_status: str

    model_config = ConfigDict(from_attributes=True)


class VoucherRedeemResponse(BaseModel):
    """Returned by ``POST /vouchers/redeem`` on success."""

    code: str
    status: str
    use_count: int
    max_uses_per_voucher: int
    redeemed_at: datetime | None
    expires_at: datetime | None

    model_config = ConfigDict(from_attributes=True)

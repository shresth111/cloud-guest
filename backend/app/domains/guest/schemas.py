"""Pydantic request/response schemas for the Guest API.

All admin/analytics response schemas follow the same pydantic v2
conventions as every other domain (``ConfigDict``, ``from_attributes``,
explicit ``Field`` descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py`` -- including
the guest-facing login/consent endpoints (mirroring OTP's/Voucher's own
guest-facing-but-still-enveloped precedent).

The RADIUS-facing schemas (``Radius*``) follow a deliberately minimal,
self-documented JSON contract rather than the standard envelope -- see
``service.py``'s module docstring for the ``rlm_rest`` architectural
write-up this mirrors.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.common.masking import MaskedIdentifier, MaskedMac, MaskedName

from .constants import GuestAuthMethod, GuestSessionStatus

__all__ = [
    "GuestOtpLoginRequest",
    "GuestVoucherLoginRequest",
    "GuestConsentRequest",
    "GuestBlockRequest",
    "SessionDisconnectRequest",
    "SessionTerminateRequest",
    "SessionPauseRequest",
    "SessionExtendRequest",
    "SessionReconnectRequest",
    "GuestDeviceResponse",
    "GuestSessionResponse",
    "GuestSessionListResponse",
    "GuestLoginResponse",
    "GuestResponse",
    "GuestDetailResponse",
    "GuestListResponse",
    "GuestConsentResponse",
    "RadiusNasRegisterRequest",
    "RadiusNasUpdateRequest",
    "RadiusNasDisableRequest",
    "RadiusNasResponse",
    "RadiusNasCreatedResponse",
    "RadiusNasListResponse",
    "RadiusAuthorizeRequest",
    "RadiusAuthorizeResponse",
    "RadiusAccountingRequest",
    "RadiusAccountingResponse",
    "GuestAnalyticsSummaryResponse",
    "TopLocationItem",
    "TopLocationsResponse",
    "TopDeviceItem",
    "TopDevicesResponse",
    "OtpSuccessRateResponse",
    "VoucherUsageResponse",
]


# ============================================================================
# Guest-facing request schemas
# ============================================================================


class GuestOtpLoginRequest(BaseModel):
    identifier: str = Field(..., min_length=3, max_length=255)
    code: str = Field(..., min_length=4, max_length=10)
    auth_method: GuestAuthMethod = Field(
        default=GuestAuthMethod.OTP_SMS,
        description="Must be otp_sms or otp_email -- which enabled-method "
        "flag on the resolved captive portal config to check.",
    )
    organization_id: uuid.UUID | None = Field(default=None)
    location_id: uuid.UUID = Field(...)
    router_id: uuid.UUID = Field(
        ..., description="The NAS (router) this guest's session will be on."
    )
    device_mac: str | None = Field(default=None, max_length=17)
    device_name: str | None = Field(default=None, max_length=200)
    ip_address: str | None = Field(default=None, max_length=45)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "identifier": "+15551234567",
                "code": "042817",
                "auth_method": "otp_sms",
                "location_id": "00000000-0000-0000-0000-000000000000",
                "router_id": "00000000-0000-0000-0000-000000000000",
                "device_mac": "AA:BB:CC:DD:EE:FF",
            }
        }
    )


class GuestVoucherLoginRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=64)
    identifier: str = Field(..., min_length=1, max_length=255)
    organization_id: uuid.UUID | None = Field(default=None)
    location_id: uuid.UUID = Field(...)
    router_id: uuid.UUID = Field(...)
    device_mac: str | None = Field(default=None, max_length=17)
    device_name: str | None = Field(default=None, max_length=200)
    ip_address: str | None = Field(default=None, max_length=45)


class GuestConsentRequest(BaseModel):
    guest_id: uuid.UUID
    captive_portal_config_id: uuid.UUID | None = Field(default=None)
    terms_version: str | None = Field(default=None, max_length=50)
    ip_address: str | None = Field(default=None, max_length=45)


# ============================================================================
# Admin-facing request schemas
# ============================================================================


class GuestBlockRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class SessionDisconnectRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=255)


class SessionTerminateRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=255)


class SessionPauseRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=255)


class SessionExtendRequest(BaseModel):
    additional_minutes: int = Field(..., gt=0, le=10080)


class SessionReconnectRequest(BaseModel):
    router_id: uuid.UUID
    location_id: uuid.UUID
    device_mac: str | None = Field(default=None, max_length=17)
    ip_address: str | None = Field(default=None, max_length=45)


# ============================================================================
# Response schemas
# ============================================================================


class GuestDeviceResponse(BaseModel):
    id: str
    guest_id: str
    mac_address: MaskedMac
    device_name: str | None
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GuestSessionResponse(BaseModel):
    id: str
    guest_id: str
    device_id: str | None
    router_id: str
    location_id: str
    organization_id: str
    auth_method: str
    voucher_id: str | None
    status: str
    started_at: datetime
    ended_at: datetime | None
    last_activity_at: datetime
    ip_address: str | None
    bytes_uploaded: int
    bytes_downloaded: int
    data_limit_mb: int | None
    session_timeout_minutes: int | None
    disconnect_reason: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GuestSessionListResponse(BaseModel):
    items: list[GuestSessionResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class GuestLoginResponse(BaseModel):
    """Returned to the guest themselves, right after they submit this
    same identifier to log in -- deliberately **not** masked (unlike
    ``GuestResponse``'s admin-facing identical field): showing a guest
    their own, just-typed phone/email back to them masked would be a
    confusing regression, not a privacy improvement, and this endpoint
    never goes through ``CurrentUser``/JWT auth at all (guests
    authenticate via OTP/voucher, not a platform ``User`` account), so
    ``MaskingContext`` would otherwise sit at its fail-closed default and
    mask it for every guest, not just privileged ones."""

    guest_id: str
    identifier: str
    is_new_guest: bool
    session: GuestSessionResponse
    device: GuestDeviceResponse | None


class GuestResponse(BaseModel):
    """Admin-/dashboard-facing -- unlike ``GuestLoginResponse``, this is
    exactly the "reception staff sees the dashboard, not raw numbers"
    view ``app.common.masking`` exists for."""

    id: str
    organization_id: str
    location_id: str | None
    identifier: MaskedIdentifier
    display_name: MaskedName
    first_seen_at: datetime
    last_seen_at: datetime
    total_visit_count: int
    is_blocked: bool
    blocked_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GuestListResponse(BaseModel):
    items: list[GuestResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class GuestDetailResponse(GuestResponse):
    sessions: list[GuestSessionResponse]


class GuestConsentResponse(BaseModel):
    id: str
    guest_id: str
    captive_portal_config_id: str | None
    consented_at: datetime
    terms_version: str | None

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# NAS admin-management schemas -- unlike the raw Authorize/Accounting
# contract further below, these ARE wrapped in the standard
# ``ApiResponse``/``build_response`` envelope by ``router.py``, the same as
# every other domain's admin-facing schema, since these are ordinary
# RBAC-gated admin CRUD, not a FreeRADIUS ``rlm_rest`` wire contract.
# ============================================================================


class RadiusNasRegisterRequest(BaseModel):
    router_id: uuid.UUID
    nas_identifier: str = Field(..., min_length=1, max_length=255)
    shared_secret: str | None = Field(
        default=None,
        min_length=8,
        max_length=255,
        description="Omit to auto-generate a cryptographically-random "
        "secret -- returned once, in the response, either way.",
    )
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    ip_address: str | None = Field(
        default=None,
        max_length=45,
        description="Defaults to the router's own public/management IP if " "omitted.",
    )


class RadiusNasUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    ip_address: str | None = Field(default=None, max_length=45)


class RadiusNasDisableRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class RadiusNasResponse(BaseModel):
    id: str
    nas_code: str | None
    router_id: str
    organization_id: str
    location_id: str
    nas_identifier: str
    status: str
    is_active: bool
    name: str | None
    description: str | None
    ip_address: str | None
    vendor: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RadiusNasCreatedResponse(RadiusNasResponse):
    """Returned only from ``POST /radius/nas`` and
    ``POST /radius/nas/{id}/regenerate-secret`` -- the one and only moment
    the plaintext shared secret is ever exposed (see ``service.py``'s
    ``RadiusNasRegistrationResult``/``RadiusNasSecretRegenerationResult``
    docstrings)."""

    shared_secret: str


class RadiusNasListResponse(BaseModel):
    items: list[RadiusNasResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# RADIUS-facing schemas -- minimal, documented JSON contract (see module
# docstring)
# ============================================================================


class RadiusAuthorizeRequest(BaseModel):
    """Shape a FreeRADIUS ``rlm_rest`` Authorize-phase call would POST --
    ``nas_identifier``/the shared secret are additionally required via
    request headers (see ``constants.RADIUS_NAS_IDENTIFIER_HEADER``/
    ``RADIUS_SHARED_SECRET_HEADER``), not this body, mirroring
    ``app.domains.router_agent``'s device-credential-via-header
    convention."""

    username: str = Field(..., description="The guest's identifier (phone/email).")


class RadiusAuthorizeResponse(BaseModel):
    authorized: bool
    session_timeout_seconds: int | None = Field(
        default=None, description="RADIUS Session-Timeout reply attribute."
    )
    data_limit_mb: int | None = Field(
        default=None, description="Bandwidth/data policy reply hint."
    )
    rate_limit: str | None = Field(
        default=None,
        description=(
            "Real Mikrotik-Rate-Limit reply attribute (rx-rate/tx-rate "
            "[burst fields...]), resolved from the session's current "
            "Queue Management Engine assignment -- None if no queue "
            "assignment exists for this session."
        ),
    )
    reply_message: str


class RadiusAccountingRequest(BaseModel):
    """Covers all three Acct-Status-Type values
    (``constants.RADIUS_ACCT_STATUS_START``/``_INTERIM_UPDATE``/``_STOP``)
    in one schema -- fields not relevant to a given ``status_type`` are
    simply left ``None``/default."""

    status_type: str = Field(..., description="One of: start, interim-update, stop.")
    session_id: uuid.UUID = Field(
        ...,
        description="The GuestSession id -- echoed back by the NAS as "
        "Acct-Session-Id, originated by this module's own login endpoints.",
    )
    bytes_uploaded_delta: int = Field(default=0, ge=0)
    bytes_downloaded_delta: int = Field(default=0, ge=0)
    bytes_uploaded_total: int | None = Field(default=None, ge=0)
    bytes_downloaded_total: int | None = Field(default=None, ge=0)
    disconnect_reason: str | None = Field(default=None, max_length=255)


class RadiusAccountingResponse(BaseModel):
    session_id: str
    status: str


# ============================================================================
# Analytics response schemas
# ============================================================================


class GuestAnalyticsSummaryResponse(BaseModel):
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


class TopLocationItem(BaseModel):
    location_id: str
    location_name: str
    session_count: int


class TopLocationsResponse(BaseModel):
    items: list[TopLocationItem]


class TopDeviceItem(BaseModel):
    device_id: str
    mac_address: str
    session_count: int
    unique_guest_count: int


class TopDevicesResponse(BaseModel):
    items: list[TopDeviceItem]


class OtpSuccessRateResponse(BaseModel):
    total_attempts: int
    successful_attempts: int
    success_rate: float


class VoucherUsageResponse(BaseModel):
    sessions: int
    unique_guests: int
    total_bandwidth_bytes: int


# Re-exported for router.py's status-filter query param.
GuestSessionStatusQuery = GuestSessionStatus

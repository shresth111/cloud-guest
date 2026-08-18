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

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

from app.common.masking import MaskedIdentifier, MaskedMac, MaskedName

from .constants import (
    PIN_LENGTH,
    RADIUS_ACCT_STATUS_INTERIM_UPDATE,
    RADIUS_ACCT_STATUS_START,
    RADIUS_ACCT_STATUS_STOP,
    GuestAuthMethod,
    GuestSessionStatus,
)

__all__ = [
    "GuestOtpLoginRequest",
    "GuestVoucherLoginRequest",
    "GuestPasswordLoginRequest",
    "GuestSetPasswordRequest",
    "GuestSetPasswordResponse",
    "GuestPinLoginRequest",
    "GuestSetPinRequest",
    "GuestSetPinResponse",
    "GuestUpdateProfileRequest",
    "GuestUpdateProfileResponse",
    "GuestConsentRequest",
    "GuestBlockRequest",
    "SessionDisconnectRequest",
    "SessionTerminateRequest",
    "SessionPauseRequest",
    "SessionExtendRequest",
    "SessionReconnectRequest",
    "GuestDeviceResponse",
    "GuestDeviceListResponse",
    "GuestLoginHistoryResponse",
    "GuestLoginHistoryListResponse",
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
        description="Must be otp_sms, otp_email, or otp_whatsapp -- which "
        "enabled-method flag on the resolved captive portal config to "
        "check.",
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


class GuestPasswordLoginRequest(BaseModel):
    """Returning-guest phone/email + password login -- the ``username_password``
    counterpart to ``GuestOtpLoginRequest``/``GuestVoucherLoginRequest``. Only
    succeeds for a guest that has already called ``POST /guest/set-password``
    once (itself only reachable after a real OTP login) -- see
    ``service.GuestService.login_via_password``'s docstring."""

    identifier: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)
    organization_id: uuid.UUID | None = Field(default=None)
    location_id: uuid.UUID = Field(...)
    router_id: uuid.UUID = Field(
        ..., description="The NAS (router) this guest's session will be on."
    )
    device_mac: str | None = Field(default=None, max_length=17)
    device_name: str | None = Field(default=None, max_length=200)
    ip_address: str | None = Field(default=None, max_length=45)


class GuestSetPasswordRequest(BaseModel):
    """Lets a guest opt in to password login right after a real OTP
    verification -- ``session_id`` is the ``GuestSession.id`` that same OTP
    login just returned (see ``GuestLoginResponse.session.id``), and is the
    *only* thing authenticating this call (there is no platform-user JWT a
    guest could ever present) -- see
    ``service.GuestService.set_guest_password``'s docstring for the full
    proof-of-recent-OTP-login write-up."""

    guest_id: uuid.UUID
    session_id: uuid.UUID
    password: str = Field(..., min_length=1, max_length=128)


class GuestSetPasswordResponse(BaseModel):
    guest_id: str
    password_set: bool


class GuestPinLoginRequest(BaseModel):
    """Portal PIN: device-scoped quick-login via a guest's own,
    previously-set PIN -- the ``pin`` counterpart to
    ``GuestPasswordLoginRequest``. Only succeeds for a guest that has
    already called ``POST /guest/set-pin`` once *and* is presenting a
    ``device_mac`` that already belongs to that same guest (see
    ``service.GuestService.login_via_pin``'s docstring). Unlike every
    other login request schema's ``device_mac``, this one is required,
    not optional -- a PIN login has nothing to verify without one."""

    identifier: str = Field(..., min_length=3, max_length=255)
    pin: str = Field(
        ..., min_length=PIN_LENGTH, max_length=PIN_LENGTH, pattern=r"^\d+$"
    )
    device_mac: str = Field(..., max_length=17)
    organization_id: uuid.UUID | None = Field(default=None)
    location_id: uuid.UUID = Field(...)
    router_id: uuid.UUID = Field(
        ..., description="The NAS (router) this guest's session will be on."
    )
    device_name: str | None = Field(default=None, max_length=200)
    ip_address: str | None = Field(default=None, max_length=45)


class GuestSetPinRequest(BaseModel):
    """Lets a guest opt in to Portal PIN login right after a real OTP
    verification -- ``session_id`` is the ``GuestSession.id`` that same
    OTP login just returned (see ``GuestLoginResponse.session.id``), and
    is the *only* thing authenticating this call, the identical shape
    ``GuestSetPasswordRequest`` already establishes (see
    ``service.GuestService.set_guest_pin``'s docstring for the full
    proof-of-recent-OTP-login write-up)."""

    guest_id: uuid.UUID
    session_id: uuid.UUID
    pin: str = Field(
        ..., min_length=PIN_LENGTH, max_length=PIN_LENGTH, pattern=r"^\d+$"
    )


class GuestSetPinResponse(BaseModel):
    guest_id: str
    pin_set: bool


class GuestUpdateProfileRequest(BaseModel):
    """The skippable "tell us about yourself" prompt shown once, right
    after a brand-new guest's first OTP verification -- ``guest_id``/
    ``session_id`` mirror ``GuestSetPasswordRequest``'s identical "prove it
    with the real ``GuestLoginResponse`` you were just issued" shape (see
    ``service.GuestService.update_guest_profile``'s docstring). Both
    profile fields are optional and independently settable; the frontend
    only calls this at all if the guest actually filled in something."""

    guest_id: uuid.UUID
    session_id: uuid.UUID
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    email: EmailStr | None = Field(default=None)


class GuestUpdateProfileResponse(BaseModel):
    guest_id: str
    display_name: str | None
    email: str | None


class GuestDisconnectRequest(BaseModel):
    """A guest ending their own connection from the captive portal's
    success screen -- ``guest_id``/``session_id`` mirror
    ``GuestSetPasswordRequest``'s identical "prove it with the real
    ``GuestLoginResponse`` you were just issued" shape (see
    ``service.GuestService.disconnect_own_session``'s docstring)."""

    guest_id: uuid.UUID
    session_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=255)


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


class GuestDeviceListResponse(BaseModel):
    """Bulk MAC-address resolution result for ``GET /guest-devices`` -- see
    ``constants.MAX_BULK_DEVICE_LOOKUP_IDS``'s own docstring. Deliberately
    has no ``page``/``page_size``/``total_items`` pagination envelope
    (unlike ``GuestSessionListResponse``): this endpoint is a bounded batch
    lookup keyed by the caller's own ``device_ids`` list, not an
    open-ended listing -- ``items`` may be shorter than the request's own
    ``device_ids`` (an id with no matching device, or one outside the
    caller's organization scope, is simply absent, not an error)."""

    items: list[GuestDeviceResponse]


class GuestLoginHistoryResponse(BaseModel):
    """One ``GuestLoginHistory`` row -- the Login/Access Attempt Log
    report's per-row shape (see ``docs/ipdr-logs-syslog-spec.md``'s v1
    recommendation). ``identifier`` reuses ``GuestResponse.identifier``'s
    own ``MaskedIdentifier`` annotation -- the same phone/email value,
    masked the same way regardless of which endpoint returns it."""

    id: str
    guest_id: str | None
    organization_id: str | None
    location_id: str | None
    identifier: MaskedIdentifier
    auth_method: str
    success: bool
    failure_reason: str | None
    attempted_at: datetime
    ip_address: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GuestLoginHistoryListResponse(BaseModel):
    items: list[GuestLoginHistoryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


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
    user_agent: str | None
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
    # Whether this guest already has a password set -- lets the
    # guest-facing frontend decide whether to show the "set a password for
    # next time?" prompt after an OTP login (skip it if already set, or if
    # this login was itself via password -- see
    # ``service.GuestService.login_via_password``, which only ever succeeds
    # for a guest that already has one).
    has_password: bool
    # The identical "let the frontend decide whether to show a set-it-up
    # prompt" signal, for Portal PIN -- see
    # ``service.GuestService.login_via_pin``, which only ever succeeds for
    # a guest that already has one *and* is on an already-recognized
    # device.
    has_pin: bool
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
    convention.

    ``calling_station_id`` is RFC 2865 Section 5.31's standard attribute
    for the connecting device's MAC address, as asserted by the NAS
    itself -- FreeRADIUS's ``rlm_rest`` always has this available (the
    NAS puts it on every real Access-Request) and forwards it verbatim
    into this call's body. This is the *only* place in this domain a MAC
    address is trusted as a login credential: unlike a value a browser
    could claim over an unauthenticated HTTP call, this one only ever
    reaches ``RadiusService.authorize`` alongside a shared-secret-
    authenticated ``nas_client`` (``dependencies.CurrentNas``), i.e. it is
    asserted by the same network equipment whose secret already proved
    it is the real NAS a device is physically connected to -- see
    ``RadiusService.authorize``'s own docstring for how this replaces the
    former public, unauthenticated ``POST /guest/login/mac`` endpoint."""

    username: str = Field(..., description="The guest's identifier (phone/email).")
    calling_station_id: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "RADIUS Calling-Station-Id (RFC 2865 Section 5.31) -- the "
            "connecting device's MAC address, as asserted by the NAS "
            "itself. Used to grant a MAC-whitelist auto-connect directly "
            "at authorize time when no session already exists for "
            "``username`` -- see ``RadiusService.authorize``'s docstring."
        ),
    )


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
    """Covers all five Acct-Status-Type values
    (``constants.RADIUS_ACCT_STATUS_START``/``_INTERIM_UPDATE``/``_STOP``/
    ``_ACCOUNTING_ON``/``_ACCOUNTING_OFF``) in one schema -- fields not
    relevant to a given ``status_type`` are simply left ``None``/default.

    ``username`` (not ``session_id``) is what actually resolves the real
    ``GuestSession`` here -- confirmed live via ``freeradius -X``: a real
    MikroTik hotspot originates its *own* Acct-Session-Id locally (a short
    NAS-internal counter like ``"80000006"``), never this platform's own
    ``GuestSession.id`` UUID -- there is no hotspot-login-form field that
    could ever hand RouterOS a caller-supplied session identifier to echo
    back. Every real Accounting-Request from a real router therefore
    always failed UUID validation before this fix. ``session_id`` is kept
    only as an opaque, NAS-originated reference string for logging/
    correlation -- the same ``_find_active_session_for_identifier``
    username-based lookup ``RadiusService.authorize`` already uses is what
    actually finds the session.

    ``username``/``session_id`` are optional (unlike the original
    three-status-type shape) because Accounting-On/Accounting-Off (RFC
    2866 §5.13) are NAS-level events, not session-level ones -- the real
    RADIUS protocol carries no Acct-Session-Id (or User-Name) on either
    packet at all, since the NAS is signalling its own boot/shutdown, not
    reporting on one specific session."""

    status_type: str = Field(
        ...,
        description=(
            "One of: start, interim-update, stop, accounting-on, " "accounting-off."
        ),
    )
    username: str | None = Field(
        default=None,
        description="The guest's identifier (RADIUS User-Name) -- resolves "
        "the currently-ACTIVE GuestSession for this NAS, the same lookup "
        "Authorize itself uses. Required for start/interim-update/stop; "
        "omitted for accounting-on/accounting-off.",
    )
    session_id: str | None = Field(
        default=None,
        description="The NAS's own Acct-Session-Id -- an opaque, "
        "NAS-originated string (e.g. RouterOS's own internal counter), "
        "kept only for logging/correlation. Never this platform's "
        "GuestSession id, and never used to look one up.",
    )
    bytes_uploaded_delta: int = Field(default=0, ge=0)
    bytes_downloaded_delta: int = Field(default=0, ge=0)
    bytes_uploaded_total: int | None = Field(default=None, ge=0)
    bytes_downloaded_total: int | None = Field(default=None, ge=0)
    disconnect_reason: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def _require_username_for_session_scoped_status_types(
        self,
    ) -> RadiusAccountingRequest:
        """``accounting-on``/``accounting-off`` are NAS-level events with no
        User-Name at all -- deliberately not enforced here (``username``
        stays ``None``/is ignored). Every other, genuinely session-scoped
        status type still requires one; this catches a malformed request
        at the schema boundary rather than letting a ``None`` reach the
        service layer's ``str``-typed ``username`` parameter."""
        session_scoped = {
            RADIUS_ACCT_STATUS_START,
            RADIUS_ACCT_STATUS_INTERIM_UPDATE,
            RADIUS_ACCT_STATUS_STOP,
        }
        if self.status_type in session_scoped and not self.username:
            raise ValueError(
                f"username is required for status_type '{self.status_type}'"
            )
        return self


class RadiusAccountingResponse(BaseModel):
    session_id: str | None = Field(
        default=None,
        description="None for accounting-on/accounting-off (NAS-level "
        "events with no single session to report on).",
    )
    status: str
    closed_session_count: int | None = Field(
        default=None,
        description="Set only for accounting-on/accounting-off: how many "
        "previously-ACTIVE sessions against this NAS were closed as stale.",
    )


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

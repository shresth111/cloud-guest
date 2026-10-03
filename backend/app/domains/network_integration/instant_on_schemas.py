"""Response/request schemas for the Aruba Instant On read API.

Every view says where its data came from (``source: "instant_on"``), when it
was read (``as_of``), and -- when it cannot be vouched for -- that it is
``unavailable`` and why, with ``items: null``. See
``instant_on_service`` for the rules. The customer schemas carry no
Instant On error text and no internal API state.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "InstantOnAccessPointItem",
    "InstantOnAccountSitesResponse",
    "InstantOnAlertItem",
    "InstantOnClientItem",
    "InstantOnClientUsageItem",
    "InstantOnCustomerView",
    "InstantOnHealthItem",
    "InstantOnPlatformView",
    "InstantOnSiteConfigRequest",
    "InstantOnSiteStatus",
    "InstantOnSitesResponse",
    "InstantOnSsidItem",
]

ItemT = TypeVar("ItemT", bound=BaseModel)


class _Item(BaseModel):
    model_config = ConfigDict(extra="ignore")


class InstantOnAccessPointItem(_Item):
    mac: str | None = None
    serial_number: str | None = None
    name: str | None = None
    model: str | None = None
    status: Literal["online", "offline", "unknown"] = "unknown"
    status_raw: str | None = None
    ip_address: str | None = None
    firmware_version: str | None = None
    uptime_seconds: int | None = None


class InstantOnClientItem(_Item):
    mac: str
    client_id: str | None = None
    name: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    connection: Literal["wireless", "wired"]
    ssid: str | None = None
    ssid_id: str | None = None
    radio_id: str | None = None
    bands: list[str] = Field(default_factory=list)
    signal_quality: str | None = None
    snr_db: int | None = None
    signal_dbm: int | None = Field(
        default=None,
        description="Always null until a dBm field is confirmed on hardware (H1).",
    )
    health: str | None = None
    status: str | None = None
    downstream_bytes: int | None = None
    upstream_bytes: int | None = None
    downstream_bps: int | None = None
    upstream_bps: int | None = None
    connected_seconds: int | None = None
    is_signed_in_guest: bool | None = Field(
        default=None,
        description=(
            "True when this MAC has an active guest session at the venue "
            "(guest data itself comes from the guest/session APIs)."
        ),
    )


class InstantOnSsidItem(_Item):
    ssid_id: str | None = None
    name: str
    enabled: bool | None = None
    network_type: str | None = None
    guest_portal_enabled: bool | None = None


class InstantOnAlertItem(_Item):
    alert_id: str | None = None
    type: str
    severity: str | None = None
    status: str | None = None
    is_cleared: bool | None = None
    raised_at: datetime | None = None
    cleared_at: datetime | None = None
    duration_seconds: int | None = None
    device_name: str | None = None


class InstantOnHealthItem(_Item):
    score: int | None = None
    status: str | None = None


class InstantOnClientUsageItem(_Item):
    client_id: str | None = None
    client_name: str | None = None
    currently_active: bool | None = None
    bytes_last_24h: int | None = None
    application_category: str | None = None


UnavailableReason = Literal[
    "not_configured", "polling_disabled", "never_polled", "poll_failed", "stale"
]


class InstantOnCustomerView(BaseModel, Generic[ItemT]):
    source: Literal["instant_on"] = "instant_on"
    kind: str
    status: Literal["ok", "unavailable"]
    unavailable_reason: UnavailableReason | None = None
    as_of: datetime | None = Field(
        default=None, description="When Instant On was read. Null when unavailable."
    )
    last_success_at: datetime | None = Field(
        default=None,
        description="Time of the last good read, also when unavailable (for "
        "'last good read HH:MM'). Never a reason to show its data.",
    )
    stale_after_seconds: int
    items: list[ItemT] | None = Field(
        default=None, description="Null (never []) when unavailable."
    )


class InstantOnPlatformView(InstantOnCustomerView[ItemT], Generic[ItemT]):
    error_code: str | None = None
    api_state: str | None = None


class InstantOnSiteConfigRequest(BaseModel):
    """Maps a NAS-only fleet router to its Instant On site. No organization
    or location here: both are copied from the router row."""

    model_config = ConfigDict(extra="forbid")

    site_id: str = Field(min_length=1, max_length=128)
    site_name: str | None = Field(default=None, max_length=255)
    poll_enabled: bool = False
    customer_visible: bool = False


class InstantOnSiteStatus(BaseModel):
    id: uuid.UUID
    router_id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    site_id: str
    site_name: str | None = None
    poll_enabled: bool
    customer_visible: bool
    api_state: str
    last_poll_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error_code: str | None = None
    last_error_message: str | None = None
    last_error_at: datetime | None = None
    consecutive_failures: int = 0
    backoff_until: datetime | None = None


class InstantOnSitesResponse(BaseModel):
    poller_enabled: bool
    service_account_configured: bool
    api_version: int
    sites: list[InstantOnSiteStatus]


class InstantOnAccountSite(BaseModel):
    site_id: str
    name: str


class InstantOnAccountSitesResponse(BaseModel):
    source: Literal["instant_on"] = "instant_on"
    status: Literal["ok", "unavailable"]
    unavailable_reason: str | None = None
    message: str | None = None
    sites: list[InstantOnAccountSite] | None = None


class InstantOnGuestRateLimitRequest(BaseModel):
    """Master: the guest SSID's per-client cap on Instant On. Integer Mbps
    (Instant On's own unit, 1..1000); both ``None`` clears the cap.
    ``dry_run`` defaults to True: nothing is written unless asked.
    ``extra="forbid"`` so a misspelt field is a 422, never a silently
    ignored no-op (the credential-shape lesson)."""

    model_config = ConfigDict(extra="forbid")

    network_id: str = Field(min_length=1, max_length=128)
    download_mbps: int | None = Field(default=None, ge=1, le=1000)
    upload_mbps: int | None = Field(default=None, ge=1, le=1000)
    dry_run: bool = True


class InstantOnGuestRateLimitState(BaseModel):
    network_id: str
    network_name: str | None = None
    enabled: bool
    download_mbps: int | None = None
    upload_mbps: int | None = None


class InstantOnGuestRateLimitResponse(BaseModel):
    source: Literal["instant_on"] = "instant_on"
    status: Literal["preview", "applied", "unavailable", "failed"]
    reason: str | None = None
    message: str | None = None
    before: InstantOnGuestRateLimitState | None = None
    requested: InstantOnGuestRateLimitState | None = None
    after: InstantOnGuestRateLimitState | None = None

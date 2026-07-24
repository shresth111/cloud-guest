"""Pydantic request/response schemas for the Router API.

Follows the same pydantic v2 conventions as ``app.domains.location.schemas``
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions).
``MessageResponse`` is re-exported from the auth domain rather than
duplicated, matching every other domain's own convention.

Credential fields (``api_username``/``api_secret``) are write-only: they
appear on the create/update request schemas but deliberately never on
``RouterResponse`` -- the encrypted ciphertext is not something any API
response should ever echo back, encrypted or not.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domains.auth.schemas import MessageResponse

from .enums import RouterStatus

__all__ = [
    "MessageResponse",
    "RouterResponse",
    "RouterListResponse",
    "RouterCreateRequest",
    "RouterUpdateRequest",
    "ProvisioningTokenResponse",
    "ProvisioningCheckInRequest",
    "ProvisioningCheckInResponse",
    "HeartbeatRequest",
]

_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _validate_mac(value: str) -> str:
    normalized = value.strip().upper()
    if not _MAC_PATTERN.match(normalized):
        raise ValueError(
            "MAC address must be in colon-separated hex form, e.g. "
            "'AA:BB:CC:DD:EE:FF'"
        )
    return normalized


# ============================================================================
# Response schemas
# ============================================================================


class RouterResponse(BaseModel):
    id: str
    location_id: str
    organization_id: str
    name: str
    serial_number: str
    mac_address: str
    model: str
    vendor: str
    routeros_version: str | None = None
    management_ip_address: str | None = None
    public_ip_address: str | None = None
    status: RouterStatus
    last_seen_at: datetime | None = None
    last_health_check_at: datetime | None = None
    health_status: str | None = None
    has_api_credentials: bool
    settings: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RouterListResponse(BaseModel):
    items: list[RouterResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ProvisioningTokenResponse(BaseModel):
    """Returned exactly once, at generation time -- ``token`` (the plaintext
    bearer credential) is never retrievable again afterward."""

    router_id: str
    token: str
    expires_at: datetime


class ProvisioningCheckInResponse(BaseModel):
    """A deliberately minimal, device-facing response shape -- see
    ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for why this endpoint's
    response is not the standard ``ApiResponse`` envelope: the calling
    device is not expected to parse a rich, user-facing API contract, only
    "did the check-in succeed and what should I do next".

    ``agent_credential``/``agent_credential_expires_at`` are an additive
    extension for ``app.domains.router_agent`` (Module 009 Part 2): the
    persistent bearer credential that module's device-facing endpoints
    (heartbeat/config-pull/status-push/action-poll) require, issued exactly
    once, right here -- the one-time provisioning token this check-in call
    just consumed is the device's last opportunity to authenticate itself
    before that credential exists, so there is no separate, later
    "activate" call the device could instead present it to. Both fields are
    optional/default ``None`` so this remains a purely additive schema
    change. See ``app.domains.router_agent.service``'s module docstring for
    the full reasoning.

    ``tunnel_ip_address``/``wireguard_server_public_key``/
    ``wireguard_endpoint_host``/``wireguard_endpoint_port``/
    ``wireguard_hub_tunnel_address`` are a second, identically-shaped
    additive extension (Module 009 Part 3, zero-touch enrollment): present
    only when the request carried ``wireguard_public_key`` -- see that
    field's own docstring on ``ProvisioningCheckInRequest`` for why the
    device, not the platform, generates this keypair. Everything a thin
    bootstrap script needs to finish bringing up its own WireGuard
    interface (the tunnel address the platform just allocated it, and the
    hub's own public key/reachable endpoint/own tunnel address) is
    returned right here, in the same one round-trip as the agent
    credential above -- for the identical "this is the device's last
    authenticated moment before the one-time token is burned" reason, not a
    second, later call. ``wireguard_hub_tunnel_address`` specifically
    exists so the device's own ``allowed-address=`` can be the hub's real
    tunnel address (a ``/32``), not a fabricated or over-broad range -- see
    ``app.domains.network_config.renderers``'s WireGuard section for why
    that parameter is correctness-critical, not cosmetic, and
    ``_hub_tunnel_address`` there for the identical derivation this
    field's value mirrors."""

    router_id: str
    status: RouterStatus
    agent_credential: str | None = Field(
        default=None,
        description=(
            "Persistent app.domains.router_agent bearer credential, shown "
            "exactly once -- never retrievable again after this response."
        ),
    )
    agent_credential_expires_at: datetime | None = Field(default=None)
    tunnel_ip_address: str | None = Field(
        default=None,
        description=(
            "This router's newly-allocated WireGuard tunnel address -- "
            "present only when the request carried wireguard_public_key."
        ),
    )
    wireguard_server_public_key: str | None = Field(
        default=None,
        description="The hub's own public key, for the device's peer entry.",
    )
    wireguard_endpoint_host: str | None = Field(
        default=None,
        description="The hub's reachable endpoint host, e.g. its public IP.",
    )
    wireguard_endpoint_port: int | None = Field(default=None)
    wireguard_hub_tunnel_address: str | None = Field(
        default=None,
        description=(
            "The hub's own tunnel-network address -- the correct, "
            "narrowest legal allowed-address=</32> for this peer's hub "
            "entry (see this class's own docstring)."
        ),
    )


# ============================================================================
# Request schemas
# ============================================================================


class RouterCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    serial_number: str = Field(..., min_length=1, max_length=100)
    mac_address: str = Field(..., min_length=17, max_length=17)
    model: str = Field(..., min_length=1, max_length=100)
    vendor: str = Field(
        default="mikrotik",
        max_length=50,
        description=(
            "Device vendor -- defaults to mikrotik (every device deployed "
            "today is one). See app.domains.router_provisioning.adapters "
            "for how a new vendor plugs into the provisioning workflow."
        ),
    )
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    api_username: str | None = Field(default=None, max_length=100)
    api_secret: str | None = Field(
        default=None,
        description=(
            "RouterOS API password or API key, stored Fernet-encrypted -- "
            "never returned by any endpoint once submitted."
        ),
    )
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, value: str) -> str:
        return _validate_mac(value)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Front Desk AP",
                "serial_number": "HB31090ABCD",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "model": "hAP ac2",
            }
        }
    )


class RouterUpdateRequest(BaseModel):
    """``location_id``/``organization_id``/``status`` are deliberately not
    fields on this schema -- location/organization are immutable after
    creation, and status is owned exclusively by the dedicated
    ``suspend``/``reinstate``/``heartbeat``/decommission (``DELETE``)
    endpoints, mirroring ``LocationUpdateRequest``'s own shape."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    serial_number: str | None = Field(default=None, min_length=1, max_length=100)
    mac_address: str | None = Field(default=None, min_length=17, max_length=17)
    model: str | None = Field(default=None, min_length=1, max_length=100)
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    api_username: str | None = Field(default=None, max_length=100)
    api_secret: str | None = Field(default=None)
    settings: dict[str, Any] | None = None

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, value: str | None) -> str | None:
        return _validate_mac(value) if value is not None else value


class ProvisioningCheckInRequest(BaseModel):
    """Presented by the physical device itself, not an authenticated
    platform user -- see ``docs/router/ROUTER_ARCHITECTURE.md`` §5.

    ``wireguard_public_key`` is an additive, optional extension (Module 009
    Part 3, zero-touch enrollment): the device's own WireGuard *public* key,
    generated on-device (RouterOS's ``/interface wireguard add`` does this
    automatically) by the thin bootstrap script this check-in call is
    typically presented from. The private half deliberately never appears
    anywhere in this request, or transits this API at all -- unlike this
    platform's existing cloud-managed model (``app.domains.wireguard``,
    where the platform generates *both* keys of a peer's pair because a
    NAT'd router cannot always be reached to self-enroll), the bootstrap
    script itself is a pasted-once, site-technician-handled artifact
    (WinBox/SSH), and a real private key embedded in it would turn that
    routinely-shared blob (commonly forwarded over WhatsApp/email between
    site techs, in practice) into a bearer credential for the tunnel
    itself. ``None`` (the default) preserves today's behavior exactly: no
    ``WireGuardPeer`` is created at check-in, the same as before this field
    existed."""

    token: str = Field(..., min_length=1)
    wireguard_public_key: str | None = Field(default=None)


class HeartbeatRequest(BaseModel):
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)

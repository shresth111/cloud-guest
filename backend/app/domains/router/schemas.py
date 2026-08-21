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
    snmp_enabled: bool
    has_snmp_community: bool
    snmp_version: str | None = None
    snmp_port: int | None = None
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
    "activate" call the device could instead present it to.
    ``agent_credential`` is required: the bootstrap script authenticates
    its very next call (``GET /agent/wireguard-config``) with it. See
    ``app.domains.router_agent.service``'s module docstring for the full
    reasoning.

    ``tunnel_ip_address``/``wireguard_server_public_key``/
    ``wireguard_endpoint_host``/``wireguard_endpoint_port``/
    ``wireguard_hub_tunnel_address`` (Module 009 Part 3, zero-touch
    enrollment) are **required, always-present** fields, exactly like
    ``agent_credential``: the bootstrap script
    (``app.domains.network_config.renderers.render_bootstrap_script``)
    hard-depends on every one of them -- it checks each by name and
    ``:error``s out on the router if any is absent -- and the endpoint now
    provisions (or, on a re-run, rotates -- see
    ``WireGuardService.ensure_tunnel_for_check_in``) the tunnel on every
    successful check-in, so declaring them required makes a platform
    regression fail loudly here, as a clear response-validation error,
    rather than on a customer's router. Everything a thin bootstrap script
    needs to finish bringing up its own WireGuard interface (the tunnel
    address the platform just allocated it, and the hub's own public
    key/reachable endpoint/own tunnel address) is returned right here, in
    the same one round-trip as the agent credential above -- for the
    identical "this is the device's last authenticated moment before the
    one-time token is burned" reason, not a second, later call.
    ``wireguard_hub_tunnel_address`` specifically
    exists so the device's own ``allowed-address=`` can be the hub's real
    tunnel address (a ``/32``), not a fabricated or over-broad range -- see
    ``app.domains.network_config.renderers``'s WireGuard section for why
    that parameter is correctness-critical, not cosmetic, and
    ``_hub_tunnel_address`` there for the identical derivation this
    field's value mirrors."""

    router_id: str
    status: RouterStatus
    agent_credential: str = Field(
        description=(
            "Persistent app.domains.router_agent bearer credential, shown "
            "exactly once -- never retrievable again after this response."
        ),
    )
    agent_credential_expires_at: datetime | None = Field(default=None)
    tunnel_ip_address: str = Field(
        description=(
            "This router's WireGuard tunnel address -- allocated on first "
            "check-in, preserved across re-runs (rotation keeps the IP)."
        ),
    )
    wireguard_server_public_key: str = Field(
        description="The hub's own public key, for the device's peer entry.",
    )
    wireguard_endpoint_host: str = Field(
        description="The hub's reachable endpoint host, e.g. its public IP.",
    )
    wireguard_endpoint_port: int
    wireguard_hub_tunnel_address: str = Field(
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
    snmp_enabled: bool = Field(
        default=False,
        description=(
            "Whether this router should be polled via SNMP for richer "
            "device metrics (CPU/memory/uptime/per-interface traffic "
            "counters) in addition to the existing RouterOS-API-based "
            "health check -- see "
            "app.domains.provisioning_engine.service"
            ".run_router_snmp_metrics_poll_sweep. Requires SNMP to "
            "actually be enabled, with a matching community string, on "
            "the physical device itself."
        ),
    )
    snmp_community: str | None = Field(
        default=None,
        description=(
            "SNMP community string (SNMPv1/v2c), stored Fernet-encrypted "
            "-- never returned by any endpoint once submitted. Falls back "
            "to the platform-wide Settings.snmp_default_community when "
            "unset and snmp_enabled is true."
        ),
    )
    snmp_version: str | None = Field(
        default=None,
        max_length=10,
        description=(
            "\"1\" or \"2c\" -- falls back to Settings.snmp_default_version "
            "when unset. SNMPv3 is not supported."
        ),
    )
    snmp_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description=(
            "SNMP agent UDP port -- falls back to "
            "Settings.snmp_default_port (161) when unset."
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
    vendor: str | None = Field(
        default=None,
        max_length=50,
        description=(
            "Device vendor -- same field/default RouterCreateRequest already "
            "exposes at creation time (router/models.py:77). Added here so "
            "an already-registered router's vendor can be corrected/set from "
            "the Master console without re-creating the router."
        ),
    )
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    api_username: str | None = Field(default=None, max_length=100)
    api_secret: str | None = Field(default=None)
    snmp_enabled: bool | None = Field(default=None)
    snmp_community: str | None = Field(default=None)
    snmp_version: str | None = Field(default=None, max_length=10)
    snmp_port: int | None = Field(default=None, ge=1, le=65535)
    settings: dict[str, Any] | None = None

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, value: str | None) -> str | None:
        return _validate_mac(value) if value is not None else value


class ProvisioningCheckInRequest(BaseModel):
    """Presented by the physical device itself, not an authenticated
    platform user -- see ``docs/router/ROUTER_ARCHITECTURE.md`` §5.

    ``wireguard_public_key`` is the **legacy** device-generated-keypair
    enrollment path (Module 009 Part 3's original shape): the device's own
    WireGuard *public* key, generated on-device by the pre-fix bootstrap
    script's own ``/interface wireguard add``. Older rendered scripts still
    in the field may present it, so it stays accepted -- when supplied, the
    device keeps its own keypair and the platform stores only the public
    half (``EXTERNALLY_MANAGED_KEY_SENTINEL``). The current script sends
    only ``token``: the platform generates the pair at check-in and the
    device pulls the private half over HTTPS from
    ``GET /agent/wireguard-config``, authenticated by the just-issued
    ``agent_credential`` -- so no key material ever rides inside the
    pasted, WhatsApp-forwardable script blob in either flow. Either way a
    ``WireGuardPeer`` now exists (or is rotated) on every successful
    check-in -- see ``WireGuardService.ensure_tunnel_for_check_in``."""

    token: str = Field(..., min_length=1)
    wireguard_public_key: str | None = Field(default=None)

    @field_validator("wireguard_public_key", mode="before")
    @classmethod
    def normalize_wireguard_public_key(cls, value: object) -> object:
        """Whitespace-only means "not supplied" -- the platform-generated
        -keypair path, never an externally-managed peer keyed by an empty
        string (see ``WireGuardService.ensure_tunnel_for_check_in``)."""
        if not isinstance(value, str):
            return value
        return value.strip() or None


class HeartbeatRequest(BaseModel):
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)


class DeviceConnectionResponse(BaseModel):
    """Decrypted device connection info -- see
    ``router.py::get_device_connection``'s own docstring for why this is
    the one endpoint in this domain that returns a plaintext credential
    rather than its encrypted-at-rest form."""

    host: str | None
    username: str | None
    password: str | None


class WebfigSessionResponse(BaseModel):
    """A short-lived, single-router-scoped opaque capability token -- see
    ``router.py``'s ``create_webfig_session`` for why this exists instead
    of just gating the WebFig proxy behind the normal ``Bearer`` auth
    every other endpoint here uses."""

    session_token: str
    expires_in: int


class BootstrapScriptPreviewResponse(BaseModel):
    """Server-rendered Step 1 bootstrap script.

    The one-time provisioning token is embedded in ``script``/``lines`` only
    -- it is minted by this call and never retrievable again afterward.

    ``mode`` echoes which rendering was produced (``onsite`` -- the
    cleanup-first fresh-enrollment paste, the default -- or ``remote`` --
    the validate-first, scheduler-staged live re-provision; see
    ``app.domains.network_config.constants.BootstrapMode``).
    ``revert_window_minutes`` is populated for ``remote`` only: how long
    the on-device automatic revert stays armed before restoring the
    previous tunnel if the cutover never confirms itself.
    """

    router_id: str
    location_code: str
    mode: str
    revert_window_minutes: int | None = None
    lines: list[str]
    script: str
    script_single_line: str = Field(
        description=(
            "The same script joined with ';' instead of newlines -- this is "
            "what a human must paste. RouterOS runs each pasted line as its "
            "own command with its own scope, so a ``:local`` set on one line "
            "is already gone by the next: a multi-line paste makes every "
            "field check fail with 'check-in response missing ...' even "
            "though the platform returned every field (confirmed on a real "
            "RouterOS 7.23.3 device). Joined with ';' the whole script runs "
            "in one scope, and ``:error`` aborts the remainder instead of "
            "letting later lines run against half-built state. Clients copy "
            "THIS field; ``script`` is for on-screen display only."
        ),
    )
    line_count: int
    token_expires_at: datetime


class DeviceInterfaceResponse(BaseModel):
    """One real, currently-available interface on the physical device --
    see ``device_adapters.list_available_device_interfaces``'s own
    docstring for what "available" excludes (already bound to a
    dhcp-server/dhcp-client, or loopback)."""

    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    has_ip_address: bool


class DeviceInterfacesResponse(BaseModel):
    interfaces: list[DeviceInterfaceResponse]

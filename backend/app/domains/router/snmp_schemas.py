"""Request/response shapes for the Master-console SNMP routes
(``app.domains.router.snmp_router``). Every secret here is write-only: a
response says whether one is set (``has_*``), never what it is."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .schemas import _validate_api_credential_charset

__all__ = [
    "RouterSnmpConfigRequest",
    "RouterSnmpStatusResponse",
    "RouterSnmpIdentityResponse",
    "RouterSnmpTestResponse",
    "RouterSnmpDeviceStateResponse",
    "RouterSnmpApplyResponse",
    "RouterSnmpScriptResponse",
]


class RouterSnmpConfigRequest(BaseModel):
    """Partial update: omitted fields are left as they are. Secrets cannot be
    blanked by sending ``""`` (refused); to stop using v3 privacy send
    ``v3_clear_privacy: true``."""

    enabled: bool | None = None
    version: Literal["2c", "3"] | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    community: str | None = Field(
        default=None,
        min_length=6,
        max_length=64,
        description="SNMPv2c community. Write-only, stored encrypted.",
    )
    v3_username: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description=(
            "SNMPv3 user name. On RouterOS a v3 user is an /snmp community "
            "row, so this is stored in the same encrypted column as the "
            "community."
        ),
    )
    v3_auth_protocol: Literal["SHA1", "MD5"] | None = None
    v3_auth_password: str | None = Field(
        default=None,
        min_length=8,
        max_length=64,
        description="USM authentication passphrase (min 8). Write-only.",
    )
    v3_priv_protocol: Literal["AES", "DES"] | None = None
    v3_priv_password: str | None = Field(
        default=None,
        min_length=8,
        max_length=64,
        description="USM privacy passphrase (min 8). Write-only.",
    )
    v3_clear_privacy: bool | None = None

    @field_validator("community", "v3_username", "v3_auth_password", "v3_priv_password")
    @classmethod
    def _charset(cls, value: str | None) -> str | None:
        # Same alphabet as the RouterOS API secret: these values are written
        # to the device and rendered into RouterOS script, where a quote or
        # a `$` would change the command.
        return _validate_api_credential_charset(value) if value is not None else value

    @model_validator(mode="after")
    def _shape(self) -> RouterSnmpConfigRequest:
        if self.community and self.v3_username:
            raise ValueError("send community (v2c) or v3_username (v3), not both")
        if self.version == "2c" and (
            self.v3_username or self.v3_auth_password or self.v3_priv_password
        ):
            raise ValueError("v3_* fields need version '3'")
        if self.version == "3" and self.community:
            raise ValueError("SNMPv3 uses v3_username, not community")
        return self


class RouterSnmpStatusResponse(BaseModel):
    router_id: uuid.UUID
    vendor: str
    #: supported | not_reachable | not_supported | unknown
    support: str
    support_reason: str
    metrics_via: str | None = None

    enabled: bool
    version: str
    port: int
    has_community: bool
    uses_platform_default_community: bool
    v3_auth_protocol: str | None = None
    has_v3_auth_password: bool = False
    v3_priv_protocol: str | None = None
    has_v3_priv_password: bool = False

    #: Where the device's community will accept requests from.
    allowed_sources: list[str]
    poll_interval_seconds: int

    last_poll_at: datetime | None = None
    #: ok | no_response | error | not_configured | None (never polled)
    last_poll_status: str | None = None
    last_poll_detail: str | None = None
    last_success_at: datetime | None = None
    device_applied_at: datetime | None = None


class RouterSnmpIdentityResponse(BaseModel):
    sys_name: str | None = None
    sys_descr: str | None = None
    uptime_seconds: int | None = None


class RouterSnmpTestResponse(BaseModel):
    ok: bool
    status: str
    detail: str | None = None
    identity: RouterSnmpIdentityResponse | None = None
    target_host: str | None = None
    target_port: int | None = None
    version: str | None = None
    tested_at: datetime


class RouterSnmpDeviceStateResponse(BaseModel):
    agent_enabled: bool
    community_present: bool
    community_disabled: bool
    community_addresses: str | None = None
    community_security: str | None = None
    community_read_only: bool | None = None
    default_public_open: bool
    other_communities: int


class RouterSnmpApplyResponse(BaseModel):
    action: str
    verified: bool
    changed: list[str]
    mismatches: list[str]
    unverified: list[str]
    state: RouterSnmpDeviceStateResponse | None = None
    allowed_sources: list[str]
    applied_at: datetime


class RouterSnmpScriptResponse(BaseModel):
    #: "apply" (SNMP enabled) or "remove" (disabled)
    action: str
    #: RouterOS commands, every secret masked.
    lines: list[str]

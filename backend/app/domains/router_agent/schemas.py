"""Pydantic request/response schemas for the Router Agent API.

Every schema here is presented/returned by a **device-facing** endpoint --
none of them use the project's standard ``ApiResponse``/``build_response``
envelope, mirroring BE-008's own ``ProvisioningCheckInResponse`` precedent
(a deliberately minimal, non-envelope response shape for the one part of an
API surface not aimed at a rich, user-facing client -- see
``docs/router/ROUTER_ARCHITECTURE.md`` §5 and this module's own
``router.py`` module docstring). The physical device calling these
endpoints is not expected to parse a rich ``{success, message, data,
request_id}`` contract, only the fact(s) it asked for.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domains.router.enums import RouterStatus

from .constants import AgentLicenseStatus

__all__ = [
    "AgentHeartbeatRequest",
    "AgentHeartbeatResponse",
    "AgentConfigResponse",
    "AgentStatusReportRequest",
    "AgentStatusReportResponse",
    "AgentActionItem",
    "AgentActionListResponse",
    "AgentActionCompleteRequest",
    "AgentActionCompleteResponse",
    "AuthorizedMacsResponse",
    "AgentNetwatchEventRequest",
    "AgentNetwatchEventResponse",
]


# Mirrors app.domains.router.schemas._validate_host_address exactly --
# management_ip_address/public_ip_address end up used as a literal `host`
# in an outbound request elsewhere in the Router domain (the WebFig proxy),
# so an unvalidated value here is a request-forgery-shaped risk, not just a
# data-quality one. Kept as a local copy rather than a cross-domain import
# of that domain's private helper, matching how _MAC_PATTERN/_validate_mac
# is never shared across domains either.
_HOSTNAME_LABEL_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _validate_host_address(value: str) -> str:
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if (
        candidate
        and len(candidate) <= 253
        and all(_HOSTNAME_LABEL_PATTERN.match(label) for label in candidate.split("."))
    ):
        return candidate
    raise ValueError(
        "must be a valid IPv4/IPv6 address or a syntactically valid hostname"
    )


# ============================================================================
# Heartbeat
# ============================================================================


class AgentHeartbeatRequest(BaseModel):
    """Identical field set to BE-008's own ``HeartbeatRequest`` -- this
    endpoint composes with ``RouterService.heartbeat`` directly, so it
    accepts exactly what that method accepts, nothing more."""

    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)
    # The router's own primary WAN (WAN1) address -- reported by
    # `buildRouterSetupScriptChunks`'s Heartbeat chunk (frontend) once it
    # started actually addressing WAN interfaces (static IP or a bound
    # DHCP lease) instead of leaving that a manual on-site step. Distinct
    # from management_ip_address (the WireGuard tunnel address this
    # platform dials back into) -- this is the outward-facing address,
    # already read elsewhere as a fallback management target (see
    # app.domains.isp.service._resolve_credentials's own
    # `router.management_ip_address or router.public_ip_address`).
    public_ip_address: str | None = Field(default=None, max_length=45)

    @field_validator("management_ip_address", "public_ip_address")
    @classmethod
    def validate_host_address(cls, value: str | None) -> str | None:
        return _validate_host_address(value) if value is not None else value


class AgentHeartbeatResponse(BaseModel):
    router_id: str
    status: RouterStatus
    last_seen_at: datetime | None = None


# ============================================================================
# Config pull
# ============================================================================


class AgentConfigResponse(BaseModel):
    """The router's current, latest-*applied* ``ConfigVersion`` content --
    never a ``draft``/``pending_apply``/``failed`` version, which would not
    be safe for a device to blindly apply outside of the
    provisioning-queue/job flow."""

    router_id: str
    version_id: str
    version_number: int
    rendered_content: str
    applied_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Status push
# ============================================================================


class AgentStatusReportRequest(BaseModel):
    """Everything a real RouterOS device agent might report about itself.
    ``routeros_version`` updates BE-008's existing ``Router.routeros_version``
    field (composed via ``RouterService.update_router``, never duplicated);
    every other field is genuinely new and stored on this module's own
    ``RouterAgentCredential`` row -- see that model's module docstring."""

    routeros_version: str | None = Field(default=None, max_length=50)
    agent_software_version: str | None = Field(
        default=None,
        max_length=100,
        description="The agent software's own version, e.g. 'cloudguest-agent 1.2.0'.",
    )
    capabilities: dict[str, Any] = Field(default_factory=dict)
    license_key: str | None = Field(default=None, max_length=255)
    license_status: AgentLicenseStatus = Field(default=AgentLicenseStatus.UNKNOWN)


class AgentStatusReportResponse(BaseModel):
    router_id: str
    agent_software_version: str | None
    license_status: AgentLicenseStatus
    recorded_at: datetime | None


# ============================================================================
# Action queue
# ============================================================================


class AgentActionItem(BaseModel):
    """A deliberately narrower shape than admin-facing
    ``ProvisioningJobResponse`` (Module 009 Part 1) -- omits
    ``requested_by_user_id``/``max_attempts``/``created_at``, facts the
    device has no use for."""

    id: str
    job_type: str
    status: str
    payload: dict[str, Any] = Field(default_factory=dict)
    attempts: int
    scheduled_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AgentActionListResponse(BaseModel):
    items: list[AgentActionItem]


class AgentActionCompleteRequest(BaseModel):
    success: bool
    error_message: str | None = Field(default=None)


class AgentActionCompleteResponse(BaseModel):
    job_id: str
    status: str


# ============================================================================
# Authorized guest MACs (portal <-> hotspot bridge)
# ============================================================================


class AuthorizedMacsResponse(BaseModel):
    """MAC addresses with a currently ``ACTIVE`` guest session on this
    router -- polled by the agent's heartbeat script alongside the regular
    heartbeat so it can apply a local hotspot ip-binding (bypassed) for
    each one, the missing link between the real captive-portal OTP flow
    (``app.domains.guest.login_via_otp``, which already accepts and stores
    ``device_mac``) and the physical device actually granting that guest
    internet access. Composes with ``GuestRepository
    .list_active_sessions_for_router``/``get_device_by_id`` directly (both
    already exist -- see that module) rather than duplicating the query."""

    mac_addresses: list[str] = Field(default_factory=list)


# ============================================================================
# Netwatch (real MikroTik RouterOS Netwatch integration)
# ============================================================================


class AgentNetwatchEventRequest(BaseModel):
    """The real, render-time-literal JSON body
    ``app.domains.network_config.renderers.render_isp_netwatch_entry``
    embeds into each ``/tool netwatch`` entry's own ``up-script``/
    ``down-script`` -- see that function's own docstring for exactly how
    it is constructed. ``status`` is restricted to ``"up"``/``"down"`` at
    this schema layer (RouterOS Netwatch itself has no third state) so
    ``validators.netwatch_status_to_ping_result`` never has to handle
    anything else."""

    isp_link_id: uuid.UUID
    status: Literal["up", "down"]
    host: str | None = Field(
        default=None,
        max_length=45,
        description=(
            "The IP address Netwatch itself was watching -- informational "
            "only (never used to resolve the link; isp_link_id already "
            "does that), recorded alongside the event for operator "
            "visibility."
        ),
    )


class AgentNetwatchEventResponse(BaseModel):
    isp_link_id: str
    health_status: str
    recorded_at: datetime | None

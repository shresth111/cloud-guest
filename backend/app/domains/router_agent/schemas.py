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

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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
]


# ============================================================================
# Heartbeat
# ============================================================================


class AgentHeartbeatRequest(BaseModel):
    """Identical field set to BE-008's own ``HeartbeatRequest`` -- this
    endpoint composes with ``RouterService.heartbeat`` directly, so it
    accepts exactly what that method accepts, nothing more."""

    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)


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

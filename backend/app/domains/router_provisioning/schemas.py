"""Pydantic request/response schemas for the Router Provisioning API.

Follows the same pydantic v2 conventions as ``app.domains.router.schemas``
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions).
``MessageResponse`` is re-exported from the auth domain rather than
duplicated, matching every other domain's own convention.

Secret-valued config variables never echo their plaintext back
(``ConfigVariableResponse.value`` is ``None`` when ``is_secret`` is true) --
the same non-echo posture ``RouterResponse.has_api_credentials`` already
established for router API credentials. The one deliberate exception is
``RouterSecretRotationResponse.new_secret``, shown exactly once at rotation
time, mirroring ``ProvisioningTokenResponse.token``'s own "shown once, never
retrievable again" convention.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domains.auth.schemas import MessageResponse

from .constants import ConfigVariableScope

__all__ = [
    "MessageResponse",
    "VendorCapabilitiesResponse",
    "VendorCapabilitiesListResponse",
    # Templates
    "ConfigTemplateCreateRequest",
    "ConfigTemplateUpdateRequest",
    "ConfigTemplateResponse",
    "ConfigTemplateListResponse",
    # Variables
    "ConfigVariableCreateRequest",
    "ConfigVariableUpdateRequest",
    "ConfigVariableResponse",
    "ConfigVariableListResponse",
    # Profiles
    "ConfigProfileAssignRequest",
    "ConfigProfileResponse",
    "ConfigProfileAssignResponse",
    # Versions
    "ConfigVersionResponse",
    "ConfigVersionSummary",
    "ConfigVersionListResponse",
    "ConfigVersionDiffResponse",
    "ConfigVersionApplyResponse",
    # Enrollment
    "RouterEnrollmentSubmitRequest",
    "RouterEnrollmentResponse",
    "RouterEnrollmentListResponse",
    "RouterEnrollmentApproveRequest",
    "RouterEnrollmentApproveResponse",
    "RouterEnrollmentRejectRequest",
    # Provisioning workflow
    "ProvisioningJobResponse",
    "ProvisioningStatusResponse",
    "RouterSecretRotationResponse",
    # Health / events
    "RouterHealthSnapshotRequest",
    "RouterHealthSnapshotResponse",
    "RouterHealthHistoryResponse",
    "RouterEventResponse",
    "RouterEventListResponse",
]


# ============================================================================
# Templates
# ============================================================================


class ConfigTemplateCreateRequest(BaseModel):
    """``organization_id``/``is_system_template`` are deliberately not
    fields on this schema -- both are derived server-side from
    ``X-Organization-Id`` (present => an org-specific custom template;
    absent => a platform-wide system template), mirroring how
    ``location_id``/``organization_id`` are never client-supplied on
    ``RouterCreateRequest`` either."""

    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(default=None)
    applicable_router_model: str | None = Field(default=None, max_length=100)
    vendor: str = Field(
        default="mikrotik",
        max_length=50,
        description=(
            "Which device vendor's config language template_content is "
            "written in -- validated against the target router's own "
            "vendor before this template may be assigned to it. Defaults "
            "to mikrotik (every existing template targets it today)."
        ),
    )
    template_content: str = Field(
        ...,
        min_length=1,
        description=(
            "Device config script/template text (the syntax of whichever "
            "vendor this template's own vendor field names). Supports "
            "'{{variable_name}}' placeholders, substituted at render time."
        ),
    )
    is_active: bool = Field(default=True)


class ConfigTemplateUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None)
    applicable_router_model: str | None = Field(default=None, max_length=100)
    template_content: str | None = Field(default=None, min_length=1)
    is_active: bool | None = Field(default=None)


class ConfigTemplateResponse(BaseModel):
    id: str
    organization_id: str | None
    is_system_template: bool
    name: str
    description: str | None
    applicable_router_model: str | None
    vendor: str
    template_content: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConfigTemplateListResponse(BaseModel):
    items: list[ConfigTemplateResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Variables
# ============================================================================


class ConfigVariableCreateRequest(BaseModel):
    """``scope_id`` is a single identifier interpreted according to
    ``scope_type``: the target router id (``ROUTER``), location id
    (``LOCATION``), or organization id (``ORGANIZATION``) -- or omitted
    entirely at ``ORGANIZATION`` scope to create a global-default variable.
    This is deliberately a single polymorphic field rather than three
    separate nullable id fields on the request, so a caller never has to
    reason about which of three fields to leave null."""

    scope_type: ConfigVariableScope
    scope_id: str | None = Field(default=None)
    key: str = Field(..., min_length=1, max_length=150)
    value: str = Field(..., min_length=1)
    is_secret: bool = Field(default=False)


class ConfigVariableUpdateRequest(BaseModel):
    value: str | None = Field(default=None, min_length=1)
    is_secret: bool | None = Field(default=None)


class ConfigVariableResponse(BaseModel):
    id: str
    scope_type: str
    organization_id: str | None
    location_id: str | None
    router_id: str | None
    key: str
    value: str | None = Field(
        default=None,
        description="Null when is_secret is true -- ciphertext is never echoed.",
    )
    is_secret: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConfigVariableListResponse(BaseModel):
    items: list[ConfigVariableResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Profiles
# ============================================================================


class ConfigProfileAssignRequest(BaseModel):
    template_id: str


class ConfigProfileResponse(BaseModel):
    id: str
    router_id: str
    template_id: str
    assigned_by_user_id: str | None
    assigned_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Versions
# ============================================================================


class ConfigVersionSummary(BaseModel):
    """A list-view row -- deliberately omits ``rendered_content`` (can be
    arbitrarily large RouterOS script text) to keep a paginated list
    response lightweight; fetch the single-version endpoint for full
    content."""

    id: str
    router_id: str
    profile_id: str | None
    version_number: int
    status: str
    is_backup: bool
    rollback_of_version_id: str | None
    created_by_user_id: str | None
    applied_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConfigVersionResponse(ConfigVersionSummary):
    rendered_content: str


class ConfigVersionListResponse(BaseModel):
    items: list[ConfigVersionSummary]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ConfigVersionDiffResponse(BaseModel):
    router_id: str
    from_version_id: str
    from_version_number: int
    to_version_id: str
    to_version_number: int
    diff_lines: list[str]


class ConfigVersionApplyResponse(BaseModel):
    version: ConfigVersionResponse
    job: ProvisioningJobResponse


class ConfigProfileAssignResponse(BaseModel):
    profile: ConfigProfileResponse
    version: ConfigVersionResponse


# ============================================================================
# Enrollment
# ============================================================================


class RouterEnrollmentSubmitRequest(BaseModel):
    """Presented by the physical device itself, before any admin-side
    ``Router`` record exists -- see ``router.py``'s module docstring for the
    minimal-identity-check reasoning (mirrors
    ``ProvisioningCheckInRequest``'s own "not a platform user" posture)."""

    serial_number: str = Field(..., min_length=1, max_length=100)
    mac_address: str = Field(..., min_length=17, max_length=17)
    model: str = Field(..., min_length=1, max_length=100)


class RouterEnrollmentResponse(BaseModel):
    id: str
    serial_number: str
    mac_address: str
    model: str
    status: str
    requested_at: datetime
    reviewed_by_user_id: str | None
    reviewed_at: datetime | None
    rejection_reason: str | None
    approved_router_id: str | None

    model_config = ConfigDict(from_attributes=True)


class RouterEnrollmentListResponse(BaseModel):
    items: list[RouterEnrollmentResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class RouterEnrollmentApproveRequest(BaseModel):
    """The device only ever supplies serial/MAC/model at submission time --
    an admin must supply the remaining ``Router``-creation fields BE-008
    requires (at minimum, which location the new device belongs to) at
    approval time."""

    location_id: str
    name: str = Field(..., min_length=1, max_length=200)
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    api_username: str | None = Field(default=None, max_length=100)
    api_secret: str | None = Field(default=None)


class RouterEnrollmentApproveResponse(BaseModel):
    enrollment: RouterEnrollmentResponse
    router_id: str


class RouterEnrollmentRejectRequest(BaseModel):
    rejection_reason: str = Field(..., min_length=1)


# ============================================================================
# Provisioning workflow
# ============================================================================


class ProvisioningJobResponse(BaseModel):
    id: str
    router_id: str
    job_type: str
    status: str
    payload: dict[str, Any] = Field(default_factory=dict)
    attempts: int
    max_attempts: int
    scheduled_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    requested_by_user_id: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProvisioningStatusResponse(BaseModel):
    router_id: str
    router_status: str
    profile: ConfigProfileResponse | None
    latest_version: ConfigVersionSummary | None
    active_jobs: list[ProvisioningJobResponse]


class RouterSecretRotationResponse(BaseModel):
    """Returned exactly once, at rotation time -- ``new_secret`` (the
    plaintext RouterOS API password/key) is never retrievable again
    afterward, mirroring ``ProvisioningTokenResponse.token``."""

    router_id: str
    api_username: str | None
    new_secret: str
    rotated_at: datetime


# ============================================================================
# Health / events
# ============================================================================


class RouterHealthSnapshotRequest(BaseModel):
    """Supplements (never replaces) BE-008's own
    ``POST /routers/{id}/heartbeat`` -- see ``router.py``'s module
    docstring. All metric fields are optional: a caller that only wants to
    refresh liveness (the original heartbeat behavior) may omit every
    metric and still get a snapshot row recorded."""

    cpu_usage_percent: float | None = Field(default=None, ge=0, le=100)
    memory_usage_percent: float | None = Field(default=None, ge=0, le=100)
    uptime_seconds: int | None = Field(default=None, ge=0)
    connected_clients_count: int | None = Field(default=None, ge=0)
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)


class RouterHealthSnapshotResponse(BaseModel):
    id: str
    router_id: str
    recorded_at: datetime
    health_status: str | None
    cpu_usage_percent: float | None
    memory_usage_percent: float | None
    uptime_seconds: int | None
    connected_clients_count: int | None

    model_config = ConfigDict(from_attributes=True)


class RouterHealthHistoryResponse(BaseModel):
    items: list[RouterHealthSnapshotResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class RouterEventResponse(BaseModel):
    id: str
    router_id: str
    event_type: str
    message: str | None
    occurred_at: datetime
    event_metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class RouterEventListResponse(BaseModel):
    items: list[RouterEventResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class VendorCapabilitiesResponse(BaseModel):
    """One registered ``ProvisioningAdapterProtocol`` implementation's real,
    static capability description -- see ``adapters.py``'s own module
    docstring."""

    vendor: str
    config_format: str
    apply_mechanism: str
    supported_job_types: list[str]
    supports_diff: bool
    supports_rollback: bool
    supports_health_snapshots: bool


class VendorCapabilitiesListResponse(BaseModel):
    items: list[VendorCapabilitiesResponse]


ConfigVersionApplyResponse.model_rebuild()

"""Pydantic schemas for the Policy domain: both the API request/response DTOs
and the per-``PolicyType`` ``rules`` payload schemas (``POLICY_RULE_SCHEMAS``)
``validators.validate_rules`` checks every ``create_version`` call against.

See ``constants.py``'s module docstring for why ``SESSION``/``AUTHN``/
``BANDWIDTH``/``QOS`` have a concrete schema below -- every other
``PolicyType`` still falls back to ``GenericPolicyRules`` (accepts any JSON
object, no further shape validation), honestly reflecting that no existing
hardcoded platform constant justifies a specific schema for those types yet.
``BandwidthPolicyRules``/``QoSPolicyRules`` were added for
``app.domains.queue_management`` (the Queue Management Engine) to compose
via ``PolicyService.resolve_effective_policy`` -- raw rate-limit/traffic-
classification values, never a reference to a ``queue_management`` row:
this module stays a dependency-free leaf (see ``constants.py``'s own
docstring); it is ``queue_management`` that depends on ``policy``, not the
reverse.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .constants import PolicyType, PolicyVersionStatus

__all__ = [
    "SessionPolicyRules",
    "AuthNPolicyRules",
    "BandwidthPolicyRules",
    "QoSPolicyRules",
    "GenericPolicyRules",
    "POLICY_RULE_SCHEMAS",
    "PolicyCreateRequest",
    "PolicyVersionCreateRequest",
    "PolicyAssignmentCreateRequest",
    "PolicyResponse",
    "PolicyVersionResponse",
    "PolicyAssignmentResponse",
    "PolicyListResponse",
    "PolicyDetailResponse",
    "ResolvedPolicyResponse",
]


# ============================================================================
# Rule payload schemas -- validated shape of PolicyVersion.rules per
# PolicyType. See module docstring.
# ============================================================================


class SessionPolicyRules(BaseModel):
    session_timeout_minutes: int = Field(..., ge=1)
    max_concurrent_sessions_per_guest: int = Field(..., ge=1)
    termination_reconnect_cooldown_minutes: int = Field(..., ge=0)
    reconnect_grace_minutes: int = Field(..., ge=0)

    model_config = ConfigDict(extra="forbid")


class AuthNPolicyRules(BaseModel):
    max_attempts_per_window: int = Field(..., ge=1)
    window_minutes: int = Field(..., ge=1)

    model_config = ConfigDict(extra="forbid")


class BandwidthPolicyRules(BaseModel):
    """Validated shape of a ``PolicyType.BANDWIDTH`` version's ``rules``
    payload -- raw rate-limit values ``app.domains.queue_management``
    composes via ``PolicyService.resolve_effective_policy`` and resolves
    into (or matches against) a real ``QueueProfile`` of its own. Rate
    fields are in kbps, matching ``QueueProfile``'s own unit -- see that
    domain's own ``FLOW.md`` for exactly how these raw values become a
    concrete queue assignment. ``None`` on a burst/priority field means
    "no burst configured"/"use the adapter's own default priority", not
    zero."""

    download_rate_kbps: int = Field(..., ge=0)
    upload_rate_kbps: int = Field(..., ge=0)
    burst_download_kbps: int | None = Field(default=None, ge=0)
    burst_upload_kbps: int | None = Field(default=None, ge=0)
    burst_threshold_kbps: int | None = Field(default=None, ge=0)
    burst_time_seconds: int | None = Field(default=None, ge=0)
    priority: int | None = Field(default=None, ge=1, le=8)

    model_config = ConfigDict(extra="forbid")


class QoSPolicyRules(BaseModel):
    """Validated shape of a ``PolicyType.QOS`` version's ``rules`` payload
    -- traffic-classification concerns distinct from
    ``BandwidthPolicyRules``'s raw rate limits (a QoS policy can exist
    without a bandwidth cap, and vice versa)."""

    traffic_class: str | None = None
    dscp_marking: str | None = None
    guaranteed_bandwidth_kbps: int | None = Field(default=None, ge=0)
    max_bandwidth_kbps: int | None = Field(default=None, ge=0)

    model_config = ConfigDict(extra="forbid")


class GenericPolicyRules(BaseModel):
    """Fallback schema for every ``PolicyType`` with no concrete rule schema
    yet -- accepts any JSON object as-is, no further shape validation. See
    ``constants.py``'s module docstring."""

    model_config = ConfigDict(extra="allow")


# Registry ``validators.validate_rules`` consults -- every PolicyType maps to
# a concrete schema; types with no seeded default (see
# constants.PLATFORM_DEFAULT_RULES) map to the generic passthrough.
POLICY_RULE_SCHEMAS: dict[PolicyType, type[BaseModel]] = {
    PolicyType.SESSION: SessionPolicyRules,
    PolicyType.AUTHN: AuthNPolicyRules,
    PolicyType.BANDWIDTH: BandwidthPolicyRules,
    PolicyType.FUP: GenericPolicyRules,
    PolicyType.BUSINESS_HOURS: GenericPolicyRules,
    PolicyType.ACCESS: GenericPolicyRules,
    PolicyType.VLAN: GenericPolicyRules,
    PolicyType.QOS: QoSPolicyRules,
    PolicyType.ROUTING: GenericPolicyRules,
}


# ============================================================================
# API request schemas
# ============================================================================


class PolicyCreateRequest(BaseModel):
    organization_id: uuid.UUID | None = Field(
        default=None,
        description="Omit (or null) for a platform-wide policy definition. "
        "Only a platform-level caller (no requesting organization) may "
        "create one of those.",
    )
    policy_type: PolicyType = Field(...)
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class PolicyVersionCreateRequest(BaseModel):
    rules: dict[str, Any] = Field(...)


class PolicyAssignmentCreateRequest(BaseModel):
    scope_type: str = Field(
        ..., description="One of app.domains.rbac.enums.ScopeType's values."
    )
    scope_id: uuid.UUID | None = Field(
        default=None, description="Required unless scope_type is 'global'."
    )
    priority: int = Field(default=0)


# ============================================================================
# API response schemas
# ============================================================================


class PolicyResponse(BaseModel):
    id: str
    organization_id: str | None
    policy_type: PolicyType
    name: str
    description: str | None
    is_active: bool
    current_version_id: str | None
    created_by_user_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyVersionResponse(BaseModel):
    id: str
    policy_id: str
    version_number: int
    status: PolicyVersionStatus
    rules: dict[str, Any]
    published_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyAssignmentResponse(BaseModel):
    id: str
    policy_id: str
    scope_type: str
    scope_id: str | None
    priority: int
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyListResponse(BaseModel):
    items: list[PolicyResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class PolicyDetailResponse(PolicyResponse):
    versions: list[PolicyVersionResponse]
    assignments: list[PolicyAssignmentResponse]


class ResolvedPolicyResponse(BaseModel):
    policy_type: PolicyType
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    rules: dict[str, Any]
    source: str = Field(
        ...,
        description="Which resolution tier produced these rules: the id of "
        "the winning PolicyAssignment's scope ('location:<id>', "
        "'organization:<id>', 'global:<policy_id>'), or the literal string "
        "'platform_default' when no assignment matched at all.",
    )

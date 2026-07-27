"""Pydantic schemas for the Policy domain: both the API request/response DTOs
and the per-``PolicyType`` ``rules`` payload schemas (``POLICY_RULE_SCHEMAS``)
``validators.validate_rules`` checks every ``create_version`` call against.

See ``constants.py``'s module docstring for why ``SESSION``/``AUTHN``/
``BANDWIDTH``/``QOS``/``FUP``/``BUSINESS_HOURS``/``VOUCHER``/``DEVICE`` have
a concrete schema below -- every other ``PolicyType`` still falls back to
``GenericPolicyRules`` (accepts any JSON object, no further shape
validation), honestly reflecting that no existing hardcoded platform
constant justifies a specific schema for those types yet.
``BandwidthPolicyRules``/``QoSPolicyRules`` were added for
``app.domains.queue_management`` (the Queue Management Engine) to compose
via ``PolicyService.resolve_effective_policy`` -- raw rate-limit/traffic-
classification values, never a reference to a ``queue_management`` row:
this module stays a dependency-free leaf (see ``constants.py``'s own
docstring); it is ``queue_management``/``guest``/``voucher`` that depend on
``policy``, not the reverse. ``FUPPolicyRules``/``BusinessHoursPolicyRules``/
``VoucherPolicyRules``/``DevicePolicyRules`` follow the identical
composition direction for ``app.domains.guest``'s quota enforcement/device-
limit and ``app.domains.voucher``'s redemption rules.
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
    "GroupLoginHoursRules",
    "GroupDataLimitRules",
    "QoSPolicyRules",
    "FUPPolicyRules",
    "TimeWindow",
    "BusinessHoursPolicyRules",
    "VoucherPolicyRules",
    "DevicePolicyRules",
    "GenericPolicyRules",
    "POLICY_RULE_SCHEMAS",
    "PolicyCreateRequest",
    "PolicyVersionCreateRequest",
    "PolicyAssignmentCreateRequest",
    "PolicyResponse",
    "PolicyVersionResponse",
    "PolicyAssignmentResponse",
    "GuestGroupAssignmentResponse",
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


class GroupLoginHoursRules(BaseModel):
    """A Group Policies group's "restrict login hours" window -- see
    ``BandwidthPolicyRules.login_hours``'s own doc comment for why this
    lives here rather than a separate policy type."""

    days: list[str] = Field(default_factory=list)
    start_time: str
    end_time: str

    model_config = ConfigDict(extra="forbid")


class GroupDataLimitRules(BaseModel):
    """A Group Policies group's optional data quota -- see
    ``BandwidthPolicyRules.data_limit``'s own doc comment."""

    quota: float = Field(..., ge=0)
    unit: str
    resets: str

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
    zero.

    ``session_timeout_minutes``/``idle_timeout_minutes``/
    ``devices_per_user``/``daily_limit_minutes``/``login_hours``/
    ``data_limit`` are *not* queue_management concerns -- they're Group
    Policies' (``CreateGroup.tsx``) own per-group settings, stored here
    because a ``BANDWIDTH`` policy is exactly what a "group" already is in
    this codebase and there is no separate group-metadata policy type.
    Bug report: "edit kaam nahi karta" -- before these fields existed here,
    the frontend never persisted them at all (see
    ``bandwidth-policy.service.ts``'s own former comment), so every reload
    read every group's session/idle timeout and devices-per-user back as
    blank; those three are *required* fields on the create/edit form, so
    clicking Edit on any already-saved group, then Save, always failed
    client-side validation with "Required." on fields the user never
    touched -- reading as "Edit is broken" even though nothing else about
    it was. All six are optional here (``None``/empty means "not set") so
    a policy created before this change, or directly via the API with only
    rate fields, still validates."""

    download_rate_kbps: int = Field(..., ge=0)
    upload_rate_kbps: int = Field(..., ge=0)
    burst_download_kbps: int | None = Field(default=None, ge=0)
    burst_upload_kbps: int | None = Field(default=None, ge=0)
    burst_threshold_kbps: int | None = Field(default=None, ge=0)
    burst_time_seconds: int | None = Field(default=None, ge=0)
    priority: int | None = Field(default=None, ge=1, le=8)
    session_timeout_minutes: int | None = Field(default=None, ge=1)
    idle_timeout_minutes: int | None = Field(default=None, ge=1)
    devices_per_user: int | None = Field(default=None, ge=1)
    daily_limit_minutes: int | None = Field(default=None, ge=1)
    login_hours: GroupLoginHoursRules | None = None
    data_limit: GroupDataLimitRules | None = None

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


class FUPPolicyRules(BaseModel):
    """Validated shape of a ``PolicyType.FUP`` (Fair Usage Policy)
    version's ``rules`` payload -- daily/weekly/monthly data and time
    caps. ``app.domains.guest`` composes this via
    ``PolicyService.resolve_effective_policy`` to enforce cumulative usage
    limits (see ``app.domains.guest.models.GuestQuotaUsage``) -- a
    period's limit field left ``None`` means "no cap for that period",
    not zero. A guest may be subject to more than one period's limit
    simultaneously (e.g. both a daily and a monthly cap)."""

    daily_data_limit_mb: int | None = Field(default=None, ge=0)
    weekly_data_limit_mb: int | None = Field(default=None, ge=0)
    monthly_data_limit_mb: int | None = Field(default=None, ge=0)
    daily_time_limit_minutes: int | None = Field(default=None, ge=0)
    weekly_time_limit_minutes: int | None = Field(default=None, ge=0)
    monthly_time_limit_minutes: int | None = Field(default=None, ge=0)

    model_config = ConfigDict(extra="forbid")


class TimeWindow(BaseModel):
    """A single named recurring time window -- structurally mirrors
    ``app.domains.queue_management.models.QueueSchedule``'s own
    ``days_of_week``/``start_time``/``end_time`` shape, but is an
    independently-defined schema: ``policy`` stays a dependency-free leaf
    (see ``constants.py``'s own docstring) and never imports
    ``queue_management``. ``days_of_week`` uses the identical ISO weekday
    convention (``0``=Monday..``6``=Sunday); an empty list means "every
    day"."""

    days_of_week: list[int] = Field(default_factory=list)
    start_time: str = Field(..., description='24-hour "HH:MM" string.')
    end_time: str = Field(..., description='24-hour "HH:MM" string.')

    model_config = ConfigDict(extra="forbid")


class BusinessHoursPolicyRules(BaseModel):
    """Validated shape of a ``PolicyType.BUSINESS_HOURS`` version's
    ``rules`` payload -- named time-of-day windows (peak hours/night mode/
    happy hours) a consuming domain resolves and acts on. This is the
    *policy* (which windows exist, and what they're named) -- the actual
    automatic bandwidth switching a "Night Mode" queue needs is
    ``app.domains.queue_management.models.QueueSchedule``'s own job (see
    that domain's ``FLOW.md`` §6); this schema informs *which*
    ``QueueTemplate``/``QueueSchedule`` combination should be used during
    each named window, it does not re-implement a second time-window
    engine."""

    peak_hours: list[TimeWindow] = Field(default_factory=list)
    night_mode: list[TimeWindow] = Field(default_factory=list)
    happy_hours: list[TimeWindow] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class VoucherPolicyRules(BaseModel):
    """Validated shape of a ``PolicyType.VOUCHER`` version's ``rules``
    payload -- redemption-time rules ``app.domains.voucher.service
    .VoucherService.redeem_voucher`` composes via
    ``PolicyService.resolve_effective_policy``, distinct from
    ``AuthNPolicyRules``'s own redemption-attempt *rate limiting* (a
    different concern: how many active vouchers a guest may simultaneously
    hold, not how fast they may attempt redemptions)."""

    max_active_vouchers_per_guest: int | None = Field(default=None, ge=1)
    allow_multi_use: bool = True
    default_validity_minutes_override: int | None = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")


class DevicePolicyRules(BaseModel):
    """Validated shape of a ``PolicyType.DEVICE`` version's ``rules``
    payload -- ``app.domains.guest.service.GuestService`` composes this to
    resolve the real per-guest device-count limit (see that module's own
    login-method enforcement, mirroring its existing concurrent-session-
    limit precedent) instead of a hardcoded constant."""

    max_devices_per_guest: int = Field(default=3, ge=1)
    require_known_device: bool = False

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
    PolicyType.FUP: FUPPolicyRules,
    PolicyType.BUSINESS_HOURS: BusinessHoursPolicyRules,
    PolicyType.ACCESS: GenericPolicyRules,
    PolicyType.VLAN: GenericPolicyRules,
    PolicyType.QOS: QoSPolicyRules,
    PolicyType.ROUTING: GenericPolicyRules,
    PolicyType.VOUCHER: VoucherPolicyRules,
    PolicyType.DEVICE: DevicePolicyRules,
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
    target_type: str = Field(
        default="none",
        description=(
            "One of app.domains.policy.constants.PolicyAssignmentTargetType's "
            "values -- an orthogonal WHO axis alongside scope_type's WHERE "
            "axis. 'none' (the default) applies to everyone within the "
            "scope; 'user'/'role' narrow it to one specific user or role."
        ),
    )
    target_id: uuid.UUID | None = Field(
        default=None, description="Required unless target_type is 'none'."
    )


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
    target_type: str
    target_id: str | None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GuestGroupAssignmentResponse(BaseModel):
    """"Which bandwidth group is this guest currently in, if any" -- backs
    the Map users modal's pre-check (see
    ``exceptions.PolicyAssignmentGuestAlreadyMappedError``'s own
    docstring). ``mapped=False`` means the guest has no active
    GUEST-targeted ``BANDWIDTH`` assignment anywhere; every other field is
    ``None`` in that case."""

    mapped: bool
    policy_id: str | None = None
    policy_name: str | None = None
    assignment_id: str | None = None


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
        "the winning PolicyAssignment's target ('user:<id>', 'role:<id>') "
        "if it was targeted, else its scope ('location:<id>', "
        "'organization:<id>', 'global:<policy_id>'), or the literal string "
        "'platform_default' when no assignment matched at all.",
    )
    user_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "The user this policy was resolved for, if any -- echoes the "
            "request's user_id so a caller can tell a per-user override was "
            "considered even when it didn't win."
        ),
    )

"""Pure, side-effect-free business-rule checks for the Router Provisioning
domain.

Every function here takes already-fetched model instances (or plain values)
and either returns ``None`` or raises one of this module's own
``exceptions``. None of these functions perform I/O -- lookups (e.g. "does a
router with this serial number already exist") are the service layer's job
(``service.py``), which fetches the row and then hands it to a validator
here to decide what it means. This mirrors ``app.domains.router.service``'s
own ``_validate_transition``/``ROUTER_STATUS_TRANSITIONS`` pattern of
keeping "what is a legal state" centralized and directly testable in
isolation from any database.
"""

from __future__ import annotations

import re
import uuid

from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router

from .constants import (
    CONFIG_VERSION_STATUS_TRANSITIONS,
    ENROLLMENT_STATUS_TRANSITIONS,
    PROVISIONING_JOB_STATUS_TRANSITIONS,
    ConfigVariableScope,
    ConfigVersionStatus,
    EnrollmentStatus,
    ProvisioningJobStatus,
)
from .exceptions import (
    BackupVersionExpectedError,
    ConfigTemplateScopeMismatchError,
    ConfigVersionRouterMismatchError,
    InvalidConfigVariableScopeError,
    InvalidConfigVersionStatusTransitionError,
    InvalidProvisioningJobStatusTransitionError,
    ProvisioningJobRetryLimitExceededError,
    ProvisioningJobRouterMismatchError,
    RouterAlreadyRegisteredError,
    RouterEnrollmentNotPendingError,
    RouterNotEligibleForConfigError,
    RouterNotEligibleForFactoryResetError,
)
from .models import ConfigVersion, ProvisioningJob, RouterEnrollmentRequest

_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# A router in any of these BE-008 lifecycle statuses can no longer
# meaningfully receive new configuration -- it has no live agent to push to,
# or is administratively frozen.
_ROUTER_STATUSES_INELIGIBLE_FOR_CONFIG = frozenset(
    {RouterStatus.DECOMMISSIONED.value, RouterStatus.SUSPENDED.value}
)

# Only a currently-reachable-or-was-recently-reachable router is a sane
# factory-reset target -- pending_provisioning/provisioning routers have
# nothing to reset yet, and suspended/decommissioned routers require an
# explicit administrative reinstatement first.
_ROUTER_STATUSES_ELIGIBLE_FOR_FACTORY_RESET = frozenset(
    {RouterStatus.ONLINE.value, RouterStatus.OFFLINE.value}
)


def normalize_mac_address(value: str) -> str:
    """Normalizes to uppercase, colon-separated form, mirroring
    ``app.domains.router.service._normalize_mac`` exactly -- this is a
    trivial, one-line pure-string helper duplicated rather than imported
    (BE-008 does not export it), not a re-implementation of any business
    rule."""
    return value.strip().upper()


def validate_mac_address_format(value: str) -> str:
    normalized = normalize_mac_address(value)
    if not _MAC_PATTERN.match(normalized):
        raise ValueError(
            "MAC address must be in colon-separated hex form, e.g. "
            "'AA:BB:CC:DD:EE:FF'"
        )
    return normalized


# ============================================================================
# Templates / variables
# ============================================================================


def validate_template_scope(
    *, is_system_template: bool, organization_id: uuid.UUID | None
) -> None:
    """``is_system_template`` must be true exactly when ``organization_id``
    is ``None`` -- see ``ConfigTemplate``'s module docstring."""
    if is_system_template != (organization_id is None):
        raise ConfigTemplateScopeMismatchError()


def validate_variable_scope(
    *,
    scope_type: ConfigVariableScope,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
    router_id: uuid.UUID | None,
) -> None:
    """Enforces which FK must be populated for a given ``scope_type`` (see
    ``ConfigVariable``'s module docstring for the denormalization rules)."""
    if scope_type == ConfigVariableScope.ROUTER:
        if router_id is None:
            raise InvalidConfigVariableScopeError(
                "router_id is required for ROUTER-scoped variables"
            )
    elif scope_type == ConfigVariableScope.LOCATION:
        if location_id is None:
            raise InvalidConfigVariableScopeError(
                "location_id is required for LOCATION-scoped variables"
            )
        if router_id is not None:
            raise InvalidConfigVariableScopeError(
                "router_id must be null for LOCATION-scoped variables"
            )
    elif scope_type == ConfigVariableScope.ORGANIZATION and (
        location_id is not None or router_id is not None
    ):
        raise InvalidConfigVariableScopeError(
            "location_id/router_id must be null for ORGANIZATION-scoped "
            "variables (organization_id may itself be null, meaning a "
            "global default)"
        )


# ============================================================================
# Config versions
# ============================================================================


def validate_router_can_receive_config(router: Router) -> None:
    if router.status in _ROUTER_STATUSES_INELIGIBLE_FOR_CONFIG:
        raise RouterNotEligibleForConfigError(router.id, router.status)


def validate_router_eligible_for_factory_reset(router: Router) -> None:
    if router.status not in _ROUTER_STATUSES_ELIGIBLE_FOR_FACTORY_RESET:
        raise RouterNotEligibleForFactoryResetError(router.id, router.status)


def validate_version_belongs_to_router(
    version: ConfigVersion, router_id: uuid.UUID
) -> None:
    if version.router_id != router_id:
        raise ConfigVersionRouterMismatchError(version.id, router_id)


def validate_backup_version(version: ConfigVersion) -> None:
    if not version.is_backup:
        raise BackupVersionExpectedError(version.id)


def validate_config_version_transition(
    current: ConfigVersionStatus, target: ConfigVersionStatus
) -> None:
    legal_targets = CONFIG_VERSION_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidConfigVersionStatusTransitionError(current.value, target.value)


# ============================================================================
# Enrollment
# ============================================================================


def validate_enrollment_pending(enrollment: RouterEnrollmentRequest) -> None:
    if enrollment.status != EnrollmentStatus.PENDING.value:
        raise RouterEnrollmentNotPendingError(enrollment.id, enrollment.status)
    # Defensive: also consult the explicit transition graph, mirroring
    # RouterService._validate_transition's "no ad hoc second place a status
    # change is permitted" discipline, even though the equality check above
    # already covers today's only two legal targets.
    if not ENROLLMENT_STATUS_TRANSITIONS.get(EnrollmentStatus.PENDING):
        raise RouterEnrollmentNotPendingError(enrollment.id, enrollment.status)


def validate_no_existing_router_conflict(
    *,
    existing_by_serial: object | None,
    existing_by_mac: object | None,
    identifier: str,
) -> None:
    if existing_by_serial is not None or existing_by_mac is not None:
        raise RouterAlreadyRegisteredError(identifier)


# ============================================================================
# Provisioning jobs
# ============================================================================


def validate_job_belongs_to_router(job: ProvisioningJob, router_id: uuid.UUID) -> None:
    if job.router_id != router_id:
        raise ProvisioningJobRouterMismatchError(job.id, router_id)


def validate_job_transition(
    current: ProvisioningJobStatus, target: ProvisioningJobStatus
) -> None:
    legal_targets = PROVISIONING_JOB_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidProvisioningJobStatusTransitionError(current.value, target.value)


def validate_job_retry_allowed(job: ProvisioningJob) -> None:
    if job.attempts >= job.max_attempts:
        raise ProvisioningJobRetryLimitExceededError(job.id, job.max_attempts)


__all__ = [
    "normalize_mac_address",
    "validate_mac_address_format",
    "validate_template_scope",
    "validate_variable_scope",
    "validate_router_can_receive_config",
    "validate_router_eligible_for_factory_reset",
    "validate_version_belongs_to_router",
    "validate_backup_version",
    "validate_config_version_transition",
    "validate_enrollment_pending",
    "validate_no_existing_router_conflict",
    "validate_job_belongs_to_router",
    "validate_job_transition",
    "validate_job_retry_allowed",
]

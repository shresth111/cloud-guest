"""Router Provisioning domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "RouterProvisioningError",
    "ConfigTemplateNotFoundError",
    "ConfigTemplateScopeMismatchError",
    "CrossOrganizationTemplateAccessError",
    "InvalidConfigVariableScopeError",
    "CrossOrganizationVariableAccessError",
    "ConfigVariableNotFoundError",
    "DuplicateConfigVariableError",
    "ConfigProfileNotFoundError",
    "ConfigVersionNotFoundError",
    "ConfigVersionRouterMismatchError",
    "InvalidConfigVersionStatusTransitionError",
    "UnresolvedTemplateVariablesError",
    "RouterNotEligibleForConfigError",
    "RouterNotEligibleForFactoryResetError",
    "BackupVersionExpectedError",
    "NoAppliedConfigToBackupError",
    "RouterEnrollmentNotFoundError",
    "RouterEnrollmentNotPendingError",
    "RouterAlreadyRegisteredError",
    "DuplicatePendingEnrollmentError",
    "ProvisioningJobNotFoundError",
    "InvalidProvisioningJobStatusTransitionError",
    "ProvisioningJobRetryLimitExceededError",
    "ProvisioningJobRouterMismatchError",
    "TemplateVendorMismatchError",
    "UnsupportedVendorError",
]


class RouterProvisioningError(CloudGuestError):
    """Base exception for router-provisioning domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


# ============================================================================
# Config templates
# ============================================================================


class ConfigTemplateNotFoundError(RouterProvisioningError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Config template not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ConfigTemplateScopeMismatchError(RouterProvisioningError):
    """``is_system_template`` must be ``True`` iff ``organization_id`` is
    ``None`` -- see ``ConfigTemplate``'s module docstring."""

    def __init__(self) -> None:
        super().__init__(
            "is_system_template must be true exactly when organization_id " "is null",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CrossOrganizationTemplateAccessError(RouterProvisioningError):
    def __init__(
        self,
        message: str = (
            "Cannot use a config template belonging to a different organization"
        ),
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


# ============================================================================
# Config variables
# ============================================================================


class InvalidConfigVariableScopeError(RouterProvisioningError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class CrossOrganizationVariableAccessError(RouterProvisioningError):
    def __init__(
        self,
        message: str = (
            "Cannot manage a config variable outside your own organization scope"
        ),
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class ConfigVariableNotFoundError(RouterProvisioningError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Config variable not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateConfigVariableError(RouterProvisioningError):
    def __init__(self, scope_type: str, key: str) -> None:
        super().__init__(
            f"A '{key}' variable already exists at {scope_type} scope for "
            "this target",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# Config profiles / versions
# ============================================================================


class ConfigProfileNotFoundError(RouterProvisioningError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Config profile not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ConfigVersionNotFoundError(RouterProvisioningError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Config version not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ConfigVersionRouterMismatchError(RouterProvisioningError):
    """A version referenced by id (diff/rollback/apply) does not belong to
    the router named in the path -- a tenant/hierarchy-consistency check,
    not merely a lookup failure."""

    def __init__(self, version_id: uuid.UUID, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Config version {version_id} does not belong to router {router_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidConfigVersionStatusTransitionError(RouterProvisioningError):
    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition config version from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class UnresolvedTemplateVariablesError(RouterProvisioningError):
    def __init__(self, missing_keys: list[str]) -> None:
        joined = ", ".join(sorted(missing_keys))
        super().__init__(
            f"Template references variables with no resolved value: {joined}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class RouterNotEligibleForConfigError(RouterProvisioningError):
    """A config version cannot be assigned/applied to a router that is not
    in an appropriate lifecycle status (e.g. ``decommissioned``)."""

    def __init__(self, router_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Router {router_id} in status '{current_status}' cannot receive "
            "configuration changes",
            status_code=status.HTTP_409_CONFLICT,
        )


class RouterNotEligibleForFactoryResetError(RouterProvisioningError):
    def __init__(self, router_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Router {router_id} in status '{current_status}' cannot be "
            "factory-reset -- only online/offline routers are eligible",
            status_code=status.HTTP_409_CONFLICT,
        )


class BackupVersionExpectedError(RouterProvisioningError):
    def __init__(self, version_id: uuid.UUID) -> None:
        super().__init__(
            f"Config version {version_id} is not a backup snapshot",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class NoAppliedConfigToBackupError(RouterProvisioningError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} has no applied configuration yet to back up",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# Enrollment
# ============================================================================


class RouterEnrollmentNotFoundError(RouterProvisioningError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Router enrollment request not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class RouterEnrollmentNotPendingError(RouterProvisioningError):
    def __init__(self, enrollment_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Enrollment request {enrollment_id} is '{current_status}', not " "pending",
            status_code=status.HTTP_409_CONFLICT,
        )


class RouterAlreadyRegisteredError(RouterProvisioningError):
    """Raised both at submission time and again at approval time (the race
    -condition re-check) when the serial number or MAC address already
    belongs to an active ``Router`` record."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            f"A router with serial number or MAC address '{identifier}' is "
            "already registered",
            status_code=status.HTTP_409_CONFLICT,
        )


class DuplicatePendingEnrollmentError(RouterProvisioningError):
    def __init__(self, identifier: str) -> None:
        super().__init__(
            f"A pending enrollment request already exists for '{identifier}'",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# Provisioning queue
# ============================================================================


class ProvisioningJobNotFoundError(RouterProvisioningError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Provisioning job not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvalidProvisioningJobStatusTransitionError(RouterProvisioningError):
    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition provisioning job from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisioningJobRetryLimitExceededError(RouterProvisioningError):
    def __init__(self, job_id: uuid.UUID, max_attempts: int) -> None:
        super().__init__(
            f"Provisioning job {job_id} already reached its retry limit "
            f"({max_attempts} attempts)",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisioningJobRouterMismatchError(RouterProvisioningError):
    def __init__(self, job_id: uuid.UUID, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Provisioning job {job_id} does not belong to router {router_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# Provisioning Engine: vendor adapters (see adapters.py's own module docstring)
# ============================================================================


class TemplateVendorMismatchError(RouterProvisioningError):
    """Raised by ``ProvisioningAdapterProtocol.validate_template_compatibility``
    (via ``RouterProvisioningService.assign_profile``) when a template's own
    ``vendor`` does not match the target router's ``vendor`` -- a real
    compatibility gap that went entirely unenforced before this Provisioning
    Engine extension."""

    def __init__(self, template_vendor: str, router_vendor: str) -> None:
        super().__init__(
            f"Template is written for vendor '{template_vendor}' but the "
            f"router is vendor '{router_vendor}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class UnsupportedVendorError(RouterProvisioningError):
    """Raised by ``adapters.get_provisioning_adapter`` when no adapter is
    registered for a given vendor string -- e.g. a router or template
    created with a vendor no ``ProvisioningAdapterProtocol`` implementation
    has been registered for yet."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No provisioning adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

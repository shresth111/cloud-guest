"""Provisioning Engine domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

This file grows across the Provisioning Engine build -- device-adapter
exceptions (``ProvisionDeviceConnectionError``/
``ProvisionDeviceOperationError``) are defined first since
``device_adapters.py`` needs them; job/step/template lifecycle exceptions
are added alongside the models/service that raise them.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "ProvisioningEngineError",
    "ProvisionDeviceConnectionError",
    "ProvisionDeviceOperationError",
    "UnsupportedDeviceVendorError",
    "ProvisionJobNotFoundError",
    "InvalidProvisionJobStatusTransitionError",
    "ProvisionJobNotRetryableError",
    "ProvisionJobRetryLimitExceededError",
    "ProvisionJobNotRollbackableError",
    "ProvisionJobHasNoAppliedVersionError",
    "ProvisionNoPriorVersionToRollBackToError",
    "ProvisionTemplateNotFoundError",
    "ProvisionNoConfigurationSourceError",
    "ProvisionMissingCredentialsError",
]


class ProvisioningEngineError(CloudGuestError):
    """Base exception for Provisioning Engine domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


# ============================================================================
# Device adapter errors (see device_adapters.py's own module docstring)
# ============================================================================


class ProvisionDeviceConnectionError(ProvisioningEngineError):
    """A real connection attempt (RouterOS API or SSH) to a device failed --
    covers both a genuine network failure and, in this sandbox, every
    single invocation (there is no live device anywhere in this environment
    to connect to). See ``device_adapters.py``'s own module docstring."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to device at '{host}': {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class ProvisionDeviceOperationError(ProvisioningEngineError):
    """A device operation (discover/push/verify/health-check/backup/
    restore/upload) failed after a connection was otherwise established."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Device operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class UnsupportedDeviceVendorError(ProvisioningEngineError):
    """Raised by ``device_adapters.get_device_adapter`` when no real
    ``BaseProvisionAdapter`` implementation is registered for a router's
    own ``vendor`` -- mirrors ``app.domains.router_provisioning.exceptions
    .UnsupportedVendorError``'s identical shape for the lighter template/
    payload adapter registry."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No device adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ============================================================================
# Job / step / template lifecycle errors (see service.py, models.py)
# ============================================================================


class ProvisionJobNotFoundError(ProvisioningEngineError):
    def __init__(self, job_id: uuid.UUID | None) -> None:
        super().__init__(
            f"Provision job '{job_id}' not found", status_code=status.HTTP_404_NOT_FOUND
        )


class InvalidProvisionJobStatusTransitionError(ProvisioningEngineError):
    """Mirrors ``app.domains.router_provisioning.exceptions
    .InvalidProvisioningJobStatusTransitionError``'s identical shape,
    consulting this domain's own ``constants.PROVISION_JOB_STATUS_TRANSITIONS``
    graph rather than that domain's."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            f"Cannot transition provision job from '{current_status}' to "
            f"'{target_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisionJobNotRetryableError(ProvisioningEngineError):
    def __init__(self, job_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Provision job '{job_id}' cannot be retried from status "
            f"'{current_status}' -- only a FAILED job may be retried",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisionJobRetryLimitExceededError(ProvisioningEngineError):
    def __init__(self, job_id: uuid.UUID, max_retries: int) -> None:
        super().__init__(
            f"Provision job '{job_id}' has already reached its retry limit "
            f"of {max_retries}",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisionJobNotRollbackableError(ProvisioningEngineError):
    def __init__(self, job_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Provision job '{job_id}' cannot be rolled back from status "
            f"'{current_status}' -- only a SUCCESS job may be rolled back",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisionJobHasNoAppliedVersionError(ProvisioningEngineError):
    def __init__(self, job_id: uuid.UUID) -> None:
        super().__init__(
            f"Provision job '{job_id}' has no applied config version to "
            "roll back from",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisionNoPriorVersionToRollBackToError(ProvisioningEngineError):
    def __init__(self, job_id: uuid.UUID) -> None:
        super().__init__(
            f"Provision job '{job_id}' has no prior config version to roll " "back to",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisionTemplateNotFoundError(ProvisioningEngineError):
    def __init__(self, template_id: uuid.UUID | None) -> None:
        super().__init__(
            f"Provision template '{template_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ProvisionNoConfigurationSourceError(ProvisioningEngineError):
    """Raised by ``PUSH_CONFIG`` when a (non-rollback) job has no
    ``provision_template_id`` *and* its router has no existing
    ``ConfigVersion`` to reapply -- there is nothing this step could
    possibly push. A job with no ``provision_template_id`` is only valid
    against a router that already has a ``ConfigProfile``/``ConfigVersion``
    assigned directly, outside this orchestrator (see
    ``models.ProvisionJob.provision_template_id``'s own docstring)."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has no provision template and no existing "
            "config version to push",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ProvisionMissingCredentialsError(ProvisioningEngineError):
    """Raised when a router has no management IP/username/decrypted secret
    stored -- the same real gap ``device_adapters.DeviceCredentials``
    depends on being resolved before any device I/O can even be attempted."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

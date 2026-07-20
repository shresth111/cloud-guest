"""Queue Management Engine domain exceptions.

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
    "QueueManagementError",
    "QueueProfileNotFoundError",
    "QueueScheduleNotFoundError",
    "QueueTemplateNotFoundError",
    "QueueAssignmentNotFoundError",
    "CrossOrganizationQueueAccessError",
    "InvalidQueueStatusTransitionError",
    "QueueTargetRouterRequiredError",
    "QueueTargetIdRequiredError",
    "QueueTargetIdNotAllowedError",
    "QueueAssignmentNotApplicableError",
    "QueueAssignmentNotRemovableError",
    "QueueDeviceConnectionError",
    "QueueDeviceOperationError",
    "UnsupportedQueueVendorError",
    "QueueMissingCredentialsError",
]


class QueueManagementError(CloudGuestError):
    """Base exception for Queue Management Engine domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class QueueProfileNotFoundError(QueueManagementError):
    def __init__(self, profile_id: uuid.UUID | None) -> None:
        super().__init__(
            f"Queue profile '{profile_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class QueueScheduleNotFoundError(QueueManagementError):
    def __init__(self, schedule_id: uuid.UUID | None) -> None:
        super().__init__(
            f"Queue schedule '{schedule_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class QueueTemplateNotFoundError(QueueManagementError):
    def __init__(self, template_id: uuid.UUID | None) -> None:
        super().__init__(
            f"Queue template '{template_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class QueueAssignmentNotFoundError(QueueManagementError):
    def __init__(self, assignment_id: uuid.UUID | None) -> None:
        super().__init__(
            f"Queue assignment '{assignment_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationQueueAccessError(QueueManagementError):
    """Mirrors ``app.domains.policy.exceptions
    .CrossOrganizationPolicyAccessError``'s identical shape -- a caller
    tried to read/mutate a row belonging to a different organization than
    its own ``requesting_organization_id``."""

    def __init__(self, entity: str, entity_id: uuid.UUID) -> None:
        super().__init__(
            f"{entity} '{entity_id}' does not belong to your organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidQueueStatusTransitionError(QueueManagementError):
    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            f"Cannot transition queue assignment from '{current_status}' to "
            f"'{target_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class QueueTargetRouterRequiredError(QueueManagementError):
    """Raised when a device-bound ``target_type`` (see
    ``constants.DEVICE_BOUND_TARGET_TYPES``) is assigned with no
    ``router_id`` -- there is no device to push the queue to."""

    def __init__(self, target_type: str) -> None:
        super().__init__(
            f"A router_id is required for target_type '{target_type}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class QueueTargetIdRequiredError(QueueManagementError):
    def __init__(self, target_type: str) -> None:
        super().__init__(
            f"A target_id is required for target_type '{target_type}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class QueueTargetIdNotAllowedError(QueueManagementError):
    def __init__(self) -> None:
        super().__init__(
            "target_id must be omitted when target_type is 'organization'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class QueueAssignmentNotApplicableError(QueueManagementError):
    def __init__(self, assignment_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Queue assignment '{assignment_id}' cannot be applied from "
            f"status '{current_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class QueueAssignmentNotRemovableError(QueueManagementError):
    def __init__(self, assignment_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Queue assignment '{assignment_id}' cannot be removed from "
            f"status '{current_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class QueueDeviceConnectionError(QueueManagementError):
    """A real connection attempt (RouterOS API) to a device failed -- see
    ``device_adapters.py``'s own module docstring for the "real client
    code, untested end-to-end here" scope note."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to device at '{host}': {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class QueueDeviceOperationError(QueueManagementError):
    """A device queue operation (create/update/delete/apply/read) failed
    after a connection was otherwise established."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Queue operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class UnsupportedQueueVendorError(QueueManagementError):
    """Raised by ``device_adapters.get_queue_adapter`` when no real
    ``BaseQueueAdapter`` implementation is registered for a router's own
    ``vendor``."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No queue adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class QueueMissingCredentialsError(QueueManagementError):
    """Raised when a router has no management IP/username/decrypted secret
    stored -- the same real gap
    ``app.domains.provisioning_engine.exceptions
    .ProvisionMissingCredentialsError`` documents, applied to queue device
    operations."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

"""QoS & VOIP Priority domain exceptions.

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
    "QosError",
    "QosTrafficRuleNotFoundError",
    "CrossOrganizationQosTrafficRuleAccessError",
    "InvalidPriorityError",
    "InvalidDscpValueError",
    "InvalidPortRangeError",
    "AmbiguousTrafficMatchError",
    "NoTrafficMatchError",
    "QosTrafficRuleNotEnabledError",
    "QosMissingCredentialsError",
    "QosDeviceConnectionError",
    "QosDeviceOperationError",
    "UnsupportedQosVendorError",
]


class QosError(CloudGuestError):
    """Base exception for QoS & VOIP Priority domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class QosTrafficRuleNotFoundError(QosError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"QoS traffic rule not found: {rule_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationQosTrafficRuleAccessError(QosError):
    """A caller acting within organization A attempted to read/mutate a
    QoS traffic rule belonging to organization B -- mirrors
    ``app.domains.hotspot.exceptions
    .CrossOrganizationHotspotProfileAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a QoS traffic rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidPriorityError(QosError):
    """Raised when ``priority`` is outside the real RouterOS 1-8 range
    (``app.domains.queue_management.constants.MIN_QUEUE_PRIORITY``/
    ``MAX_QUEUE_PRIORITY``)."""

    def __init__(self, priority: int, minimum: int, maximum: int) -> None:
        super().__init__(
            f"Invalid priority '{priority}': must be between {minimum} and {maximum}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidDscpValueError(QosError):
    """Raised when ``dscp_value`` is outside the real IETF DSCP 0-63
    range."""

    def __init__(self, value: int, minimum: int, maximum: int) -> None:
        super().__init__(
            f"Invalid DSCP value '{value}': must be between {minimum} and {maximum}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidPortRangeError(QosError):
    """Raised when ``port_range_start``/``port_range_end`` are not both
    real ports (1-65535) with start <= end."""

    def __init__(self, start: int, end: int, reason: str) -> None:
        super().__init__(
            f"Invalid port range '{start}'-'{end}': {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class AmbiguousTrafficMatchError(QosError):
    """Raised when a rule supplies both a port-range match and a DSCP
    match -- exactly one match kind is allowed per rule (see
    ``validators.py``)."""

    def __init__(self) -> None:
        super().__init__(
            "A QoS traffic rule must match by port range or DSCP value, not both",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class NoTrafficMatchError(QosError):
    """Raised when a rule supplies neither a port-range match nor a DSCP
    match -- a rule that matches nothing is not useful."""

    def __init__(self) -> None:
        super().__init__(
            "A QoS traffic rule must match by port range or DSCP value",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class QosTrafficRuleNotEnabledError(QosError):
    """Raised by ``push_rule_to_device`` when asked to push a rule whose
    ``is_enabled`` is ``False`` -- there is nothing correct to push: the
    mangle mark this rule's identifier would reference is never rendered
    by ``network_config`` for a disabled rule (see
    ``NetworkConfigService._gather_enabled_rows``'s own ``is_enabled``
    filter), so pushing a paired ``/queue tree`` entry anyway would create
    a queue that references a mark nothing on the device ever sets."""

    def __init__(self, rule_id: uuid.UUID) -> None:
        super().__init__(
            f"QoS traffic rule '{rule_id}' is disabled -- enable it before "
            "pushing its priority queue to the device",
            status_code=status.HTTP_409_CONFLICT,
        )


class QosMissingCredentialsError(QosError):
    """Raised when a rule's own router has no management IP/username/
    decrypted secret stored -- mirrors ``app.domains.queue_management
    .exceptions.QueueMissingCredentialsError`` exactly."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class QosDeviceConnectionError(QosError):
    """A real connection attempt (RouterOS API) to a device failed -- see
    ``device_adapters.py``'s own module docstring for the "real client
    code, untested end-to-end here" scope note."""

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to device at '{host}': {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class QosDeviceOperationError(QosError):
    """A device priority-queue operation (create/set-priority/remove)
    failed after a connection was otherwise established."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"QoS priority queue operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class UnsupportedQosVendorError(QosError):
    """Raised by ``device_adapters.get_qos_queue_adapter`` when no real
    adapter implementation is registered for a router's own ``vendor``."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No QoS priority queue adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

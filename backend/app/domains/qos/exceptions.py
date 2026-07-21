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

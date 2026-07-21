"""Pure validation helpers for the QoS & VOIP Priority domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

from .constants import MAX_DSCP_VALUE, MAX_PRIORITY, MIN_DSCP_VALUE, MIN_PRIORITY
from .exceptions import (
    AmbiguousTrafficMatchError,
    InvalidDscpValueError,
    InvalidPortRangeError,
    InvalidPriorityError,
    NoTrafficMatchError,
)

_MIN_PORT = 1
_MAX_PORT = 65535


def validate_priority(priority: int) -> None:
    if not (MIN_PRIORITY <= priority <= MAX_PRIORITY):
        raise InvalidPriorityError(priority, MIN_PRIORITY, MAX_PRIORITY)


def validate_dscp_value(value: int | None) -> None:
    """No-op if ``value`` is ``None``."""
    if value is None:
        return
    if not (MIN_DSCP_VALUE <= value <= MAX_DSCP_VALUE):
        raise InvalidDscpValueError(value, MIN_DSCP_VALUE, MAX_DSCP_VALUE)


def validate_port_range(start: int, end: int) -> None:
    if not (_MIN_PORT <= start <= _MAX_PORT):
        raise InvalidPortRangeError(start, end, f"'{start}' is not a valid port")
    if not (_MIN_PORT <= end <= _MAX_PORT):
        raise InvalidPortRangeError(start, end, f"'{end}' is not a valid port")
    if start > end:
        raise InvalidPortRangeError(start, end, "start must not be after end")


def validate_traffic_match(
    *,
    port_range_start: int | None,
    port_range_end: int | None,
    dscp_value: int | None,
) -> None:
    """Exactly one match kind is required: a port range (both bounds
    present) or a DSCP value -- never both, never neither. See
    ``models.QosTrafficRule``'s own module docstring for why."""
    has_port_match = port_range_start is not None or port_range_end is not None
    has_dscp_match = dscp_value is not None

    if has_port_match and has_dscp_match:
        raise AmbiguousTrafficMatchError()
    if not has_port_match and not has_dscp_match:
        raise NoTrafficMatchError()
    if has_port_match:
        if port_range_start is None or port_range_end is None:
            raise InvalidPortRangeError(
                port_range_start or 0,
                port_range_end or 0,
                "both port_range_start and port_range_end are required together",
            )
        validate_port_range(port_range_start, port_range_end)
    else:
        validate_dscp_value(dscp_value)


__all__ = [
    "validate_priority",
    "validate_dscp_value",
    "validate_port_range",
    "validate_traffic_match",
]

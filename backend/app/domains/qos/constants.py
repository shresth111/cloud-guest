"""Constants for the QoS & VOIP Priority domain.

``MIN_PRIORITY``/``MAX_PRIORITY``/``DEFAULT_PRIORITY`` are re-exported
directly from ``app.domains.queue_management.constants`` -- the real,
already-established RouterOS ``/queue simple``/``/queue tree`` priority
range (1-8) -- rather than redeclared, so the two domains can never
silently drift apart.
"""

from __future__ import annotations

from enum import StrEnum

from app.domains.queue_management.constants import (
    DEFAULT_QUEUE_PRIORITY as DEFAULT_PRIORITY,
)
from app.domains.queue_management.constants import (
    MAX_QUEUE_PRIORITY as MAX_PRIORITY,
)
from app.domains.queue_management.constants import (
    MIN_QUEUE_PRIORITY as MIN_PRIORITY,
)

# DSCP (Differentiated Services Code Point) is a real, IETF-standard
# 6-bit field (RFC 2474) -- 0-63 is not this codebase's own choice, it is
# the field's own hard width.
MIN_DSCP_VALUE = 0
MAX_DSCP_VALUE = 63


class QosProtocol(StrEnum):
    """Which transport protocol a port-range match applies to. Unlike
    ``app.domains.port_forwarding.constants.PortForwardingProtocol``,
    there is deliberately no ``BOTH`` value here -- a real RouterOS
    ``/ip firewall mangle`` rule matching ``dst-port`` requires an
    explicit ``protocol=tcp`` or ``protocol=udp``; matching both
    transports needs two separate mangle rules, not one rule with an
    omitted protocol (unlike a DSTNAT rule, where omitting ``protocol``
    is itself a valid "match everything" instruction)."""

    TCP = "tcp"
    UDP = "udp"


__all__ = [
    "MIN_PRIORITY",
    "MAX_PRIORITY",
    "DEFAULT_PRIORITY",
    "MIN_DSCP_VALUE",
    "MAX_DSCP_VALUE",
    "QosProtocol",
]

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
from app.domains.queue_management.constants import UNLIMITED_RATE_KBPS

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


class QosDevicePushStatus(StrEnum):
    """Lifecycle of a :class:`~.models.QosTrafficRule`'s own paired
    ``/queue tree`` device push -- distinct from ``is_enabled`` (whether
    the rule *should* be active) and independent of whatever state the
    mangle-mark half is in (that half is realized by
    ``app.domains.network_config``'s own separate ``ConfigVersion``/
    ``ProvisioningJob`` pipeline, which tracks its own status). See
    ``service.py::push_rule_to_device``'s own docstring for the full
    device-push write-up.

    * ``PENDING`` -- created, never yet pushed (or a previous device
      queue was removed and not yet re-pushed).
    * ``ACTIVE`` -- a real ``/queue tree`` entry for this rule exists on
      the router right now (``device_queue_id`` is set and current).
    * ``FAILED`` -- the most recent push attempt raised a real device
      error (connection or RouterOS command failure); ``device_queue_id``
      may still reference a stale/nonexistent device row if the failure
      happened on a re-push rather than the first push -- see
      ``push_rule_to_device``'s own handling.
    """

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


# The RouterOS ``/queue tree`` ``parent`` value used for every priority
# queue this domain pushes. ``QosTrafficRule`` has no interface column of
# its own (unlike e.g. ``DhcpPool.interface``/``Vlan.interface``) to
# derive a real, specific per-interface parent from -- a traffic-
# classification rule matches packets by protocol/port/DSCP, not by which
# physical interface they arrive or depart on. ``"global"`` is RouterOS's
# own real, built-in special parent representing total router-wide
# traffic (MikroTik's own published ``/queue tree`` reference lists it
# alongside real interface names as a valid ``parent=`` value) -- the
# correct choice for "prioritize this marked traffic everywhere on this
# router," not a fabricated placeholder. **Not confirmed against a real
# device this session** (no live MikroTik hardware in this environment,
# see ``device_adapters.py``'s own module docstring) -- flagged honestly
# rather than claimed verified, mirroring this codebase's existing
# convention for exactly this situation (e.g. ``network_config.renderers``
# module docstring's own "not independently confirmed" paragraphs).
QOS_QUEUE_TREE_PARENT = "global"

# ``/queue tree``'s own ``max-limit`` field is required, but this domain
# tracks priority/classification only, never a bandwidth ceiling (that
# remains entirely ``app.domains.queue_management``'s concern -- see
# ``models.py``'s own "Scope" section). Reuses
# ``app.domains.queue_management.constants.UNLIMITED_RATE_KBPS`` (``0``)
# directly rather than a second, independently-chosen literal -- the same
# "0 means unlimited" RouterOS convention that module's own
# ``format_mikrotik_rate_limit`` docstring already documents for
# ``/queue simple``, and MikroTik's own ``/queue tree`` reference
# documents identically for ``max-limit`` (default ``0``, "no limit").
QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS = UNLIMITED_RATE_KBPS


__all__ = [
    "MIN_PRIORITY",
    "MAX_PRIORITY",
    "DEFAULT_PRIORITY",
    "MIN_DSCP_VALUE",
    "MAX_DSCP_VALUE",
    "QosProtocol",
    "QosDevicePushStatus",
    "QOS_QUEUE_TREE_PARENT",
    "QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS",
]

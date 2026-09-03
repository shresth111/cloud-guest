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
    """Lifecycle of a :class:`~.models.QosTrafficRule`'s own device push
    -- both halves of it, the ``/ip firewall mangle`` mark and the
    ``/queue tree`` entry that references it. Distinct from ``is_enabled``
    (whether the rule *should* be active). See
    ``service.py::push_rule_to_device``'s own docstring for the full
    device-push write-up.

    * ``PENDING`` -- created, never yet pushed; or pushed and then edited
      in a way the router does not know about (see
      ``DEVICE_CARRIED_FIELDS`` below); or a previous device queue was
      removed and not yet re-pushed.
    * ``ACTIVE`` -- a real mangle rule *and* a real ``/queue tree`` entry
      for this rule exist on the router right now, carrying these exact
      values. This is what the customer-facing "Applied to your router"
      badge renders, so it may never be written for a push that realized
      only part of the mechanism.
    * ``FAILED`` -- the most recent push attempt raised a real device
      error (connection or RouterOS command failure). The record is
      committed before the exception propagates, so it survives the
      session rollback and is actually readable afterward;
      ``device_queue_id`` may still reference a device row created earlier
      in the same push, which is why the gateway's ``create_queue_tree``
      finds an existing queue by name rather than trusting that column.
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


# Every column ``QosService.push_rule_to_device`` actually puts on the
# router. ``protocol``/``port_range_start``/``port_range_end``/
# ``dscp_value`` are the mangle rule's own match conditions, and
# ``priority`` is the ``/queue tree`` field the whole feature exists to
# set. Changing any of them makes an ``ACTIVE`` row describe a
# classification the device is not performing -- see
# ``app.common.device_push``.
#
# ``name`` is in this set, and it is the one domain where a display name
# genuinely is device configuration:
# ``identifiers.qos_packet_mark_identifier`` derives the RouterOS packet
# mark from ``name`` + the row id, so a rename changes the real
# ``new-packet-mark`` on the mangle rule and the ``packet-mark`` the queue
# tree references. ``push_rule_to_device`` already has to remove and
# recreate the device objects for exactly this reason; leaving the row
# ``active`` through a rename would say the router is prioritising a mark
# it has never been told about.
#
# ``is_enabled`` is not here: it is intent, not configuration -- see
# ``app.common.device_push``'s own note.
DEVICE_CARRIED_FIELDS = frozenset(
    {
        "name",
        "protocol",
        "port_range_start",
        "port_range_end",
        "dscp_value",
        "priority",
    }
)


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
    "DEVICE_CARRIED_FIELDS",
]

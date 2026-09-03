"""Enumerations and small constants for the Port Forwarding Management
domain.

``PortForwardingProtocol`` is stored as a plain ``String`` column, never a
native PostgreSQL enum type -- the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration, only a new additive ``StrEnum`` member.
"""

from __future__ import annotations

from enum import StrEnum

# Real TCP/UDP port bounds -- port 0 is reserved ("any"/wildcard, not a
# real forwardable port), 65535 is the real maximum.
MIN_PORT = 1
MAX_PORT = 65535


class PortForwardingProtocol(StrEnum):
    """Which transport protocol(s) a rule matches. ``BOTH`` matches
    either TCP or UDP -- conflict detection (service.py) treats ``BOTH``
    as overlapping with every other protocol value, mirroring how a real
    RouterOS DSTNAT rule with no ``protocol`` restriction matches every
    transport."""

    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"


class PortForwardingDevicePushStatus(StrEnum):
    """Lifecycle of a :class:`~.models.PortForwardingRule`'s own device
    push.

    Distinct from ``is_enabled``, which is intent ("this rule should
    forward"), and independent of ``network_config``'s ``ConfigVersion``
    status -- that pipeline renders a script and ships it over SSH on port
    22, which is filtered on the fleet; this is a direct RouterOS-API push
    on 8728. A rule can be enabled, rendered into a config version, and
    still never have reached a device.

    * ``PENDING`` -- created, never pushed. The state every pre-existing
      row is backfilled to, truthfully: until now no code path could push
      one.
    * ``ACTIVE`` -- a real ``/ip firewall nat`` DSTNAT rule for this row
      exists on the router (two of them, for a ``BOTH`` rule -- see
      ``mikrotik_adapter.configure_port_forward``).
    * ``FAILED`` -- the last push attempt raised; ``device_push_error``
      holds the device's own words.
    """

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


__all__ = [
    "MIN_PORT",
    "MAX_PORT",
    "PortForwardingProtocol",
    "PortForwardingDevicePushStatus",
]

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


__all__ = ["MIN_PORT", "MAX_PORT", "PortForwardingProtocol"]

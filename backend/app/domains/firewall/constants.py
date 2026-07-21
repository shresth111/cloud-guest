"""Enumerations and small constants for the Firewall Rule Management
domain.

Every enum here is stored as a plain ``String`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration, only a new additive ``StrEnum`` member.
"""

from __future__ import annotations

from enum import StrEnum

MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_PRIORITY = 100


class FirewallChain(StrEnum):
    """Which real RouterOS ``/ip firewall filter`` chain this rule
    belongs to."""

    INPUT = "input"
    FORWARD = "forward"
    OUTPUT = "output"


class FirewallAction(StrEnum):
    """What a matching packet does. ``TARPIT``/``LOG`` and other real
    RouterOS actions exist but are deliberately left out of this first
    pass -- only the three most common actions any real deployment
    actually reaches for are modeled."""

    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class FirewallProtocol(StrEnum):
    """Which transport protocol a rule matches. ``ALL`` matches every
    protocol -- mirrors ``app.domains.port_forwarding.constants
    .PortForwardingProtocol.BOTH``'s identical "omit the protocol=
    parameter entirely" rendering, the real RouterOS equivalent of "any"."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


__all__ = [
    "MIN_PORT",
    "MAX_PORT",
    "DEFAULT_PRIORITY",
    "FirewallChain",
    "FirewallAction",
    "FirewallProtocol",
]

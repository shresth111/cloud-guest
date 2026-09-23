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


class FirewallDevicePushStatus(StrEnum):
    """Whether this rule is on its router right now, as a
    :class:`~.models.FirewallRule`'s own device push last left it.

    Same three values and the same meaning as
    ``content_filtering.constants.ContentFilterDevicePushStatus``, with one
    difference that follows from how this domain pushes: a push is per
    *router*, because a rule's position in the chain is a property of the
    whole set (``priority`` orders them inside the sentinel band), so every
    enabled rule on the router lands together or not at all.

    * ``PENDING`` -- not on the device: never pushed, edited since, or
      disabled (a disabled rule is taken off the router by the next push).
    * ``ACTIVE`` -- the last push put exactly this rule, with these fields,
      inside the router's sentinel band, and read it back there. A claim
      about the chain's contents, not that a packet was ever matched.
    * ``FAILED`` -- the last push attempt for this router raised;
      ``device_push_error`` holds the device's or the refusal's own words.
    """

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


#: Columns the push writes onto the router. Changing one on an ``ACTIVE``
#: row demotes it to ``PENDING`` (``app.common.device_push``).
#:
#: ``is_enabled`` IS listed here, unlike every other domain's copy of this
#: tuple, and deliberately: this push is a desired-state push of the router's
#: whole rule set, so disabling a rule is exactly what removes it from the
#: device at the next push. Until then the router still carries it, and an
#: ``ACTIVE`` badge on a disabled rule would be a claim the device contradicts.
#: ``name`` and ``comment`` are absent: neither reaches the device -- the
#: device comment is the rule's id, never the customer's text.
DEVICE_CARRIED_FIELDS: tuple[str, ...] = (
    "chain",
    "action",
    "protocol",
    "source_address",
    "destination_address",
    "source_port",
    "destination_port",
    "in_interface",
    "priority",
    "is_enabled",
)


__all__ = [
    "DEVICE_CARRIED_FIELDS",
    "FirewallDevicePushStatus",
    "MIN_PORT",
    "MAX_PORT",
    "DEFAULT_PRIORITY",
    "FirewallChain",
    "FirewallAction",
    "FirewallProtocol",
]

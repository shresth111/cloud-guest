"""What a venue owner may see of their own router's interfaces.

## Why this module exists

``RouterHealthSnapshot.interface_traffic_counters`` is whatever the SNMP
sweep read off the device -- every interface the IF-MIB reported, with its
byte counters. On a provisioned MikroTik that list includes
``wg-cloudguard``: the WireGuard tunnel this platform builds to manage the
device. It was reaching the customer Devices screen, rendered next to
``ether1``-``ether5`` and ``bridge`` as a working interface with traffic on
it (258 KB in / 631 KB out, the run that found this).

``GET /routers/{id}/health-history`` is ``router_provisioning.read`` at
**organization** scope, so it is a venue-owner-facing payload, and tunnel
internals are Master-console and backend only -- permanently, and not as a
matter of taste: the interface name, its state and its byte counters together
tell a customer that a management tunnel exists, that it is up, and roughly
how much this platform talks to their device.

The console now filters these too. That is defence in depth and it is the
right place for a second line, but a payload that carries the field and a
client that declines to draw it is still a payload that carries the field --
it is in the JSON, in any log or proxy that records a response body, and in
whatever the next client to consume this endpoint does with it.

## Why a shape, not just the one name

``WIREGUARD_INTERFACE_NAME`` is a fixed literal today and the exact-match
would be enough today. It is matched by prefix family as well because the
cost of over-filtering is one row a venue owner never needed, and the cost of
under-filtering is a tunnel disclosed by a rename nobody connected to this
file. A venue's own interfaces are ``ether*``, ``bridge*``, ``wlan*``,
``vlan*``, ``sfp*``, ``pppoe*`` -- none of which collide with the families
below.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "PLATFORM_TUNNEL_INTERFACE_PREFIXES",
    "customer_visible_interface_counters",
    "is_platform_tunnel_interface",
]

#: Interface-name families that are this platform's own plumbing rather than
#: the venue's network. ``wg`` covers ``wg-cloudguard`` and any successor;
#: the rest are the tunnel types RouterOS can carry and that a venue would
#: not be running on its own guest WiFi box.
PLATFORM_TUNNEL_INTERFACE_PREFIXES: tuple[str, ...] = (
    "wg",
    "wireguard",
    "tun",
    "tap",
    "gre",
    "ipip",
    "eoip",
    "l2tp",
    "sstp",
    "ovpn",
)


def is_platform_tunnel_interface(if_name: str | None) -> bool:
    """True when this interface is platform plumbing, not venue equipment."""
    if not if_name:
        return False
    folded = if_name.strip().lower()
    return any(
        folded.startswith(prefix) for prefix in PLATFORM_TUNNEL_INTERFACE_PREFIXES
    )


def customer_visible_interface_counters(
    counters: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    """``counters`` with every platform tunnel interface removed.

    ``None`` is preserved as ``None`` rather than flattened to ``[]``: the
    two mean different things on this field and always have -- ``None`` is
    "this snapshot has no SNMP interface reading at all" (a RouterOS-API
    sourced row, or one written before migration 0079), and ``[]`` is "SNMP
    answered and reported no interfaces". Turning the first into the second
    would be exactly the fabricated-zero this schema's own docstring refuses.
    """
    if counters is None:
        return None
    return [
        counter
        for counter in counters
        if not is_platform_tunnel_interface(counter.get("if_name"))
    ]

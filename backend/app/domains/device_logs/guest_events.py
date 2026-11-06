"""Guest-relevant device events, derived from (already masked) device log
lines: which IP a device was given and released by the router's DHCP
server, and when the router's hotspot signed a client in or out.

These rows exist so the customer's Guest Connection Records can show, per
guest session, what the venue's router said about *that* session's device --
and nothing else. So the parser is deliberately narrow:

* **Only four message shapes are recognised**, all anchored on the whole
  message body. Anything else -- router admin logins (``user admin logged in
  from ... via winbox``, which also says "logged in"), firewall, system,
  failed hotspot logins, DHCP offers -- produces nothing.
* **Nothing personal beyond MAC and IP is kept.** The DHCP line's trailing
  client host name ("Rahuls-iPhone") and the hotspot user name (the guest's
  phone number, already masked upstream) are parsed past and dropped.

Formats (RouterOS 7, ``remote-log-format=syslog``; the body is what follows
the ``wyfy-<tag>:`` prefix):

==========================  ==================================================
DHCP, RouterOS 7            ``<server> assigned <ip> for <mac> [<host name>]``
                            ``<server> deassigned <ip> for <mac> [<host name>]``
DHCP, RouterOS 6            ``<server> assigned <ip> to <mac>``
                            ``<server> deassigned <ip> from <mac>``
Hotspot (both)              ``<user> (<ip>): logged in``
                            ``<user> (<ip>): logged out: <reason>``
==========================  ==================================================

Provenance, stated honestly: as of 2026-10-07 no DHCP or hotspot line has
yet reached our collector (prod holds only system/fetch lines from one
router), so these shapes come from RouterOS's documented log output and the
parser's existing fixtures, not from our fleet. A shape the fleet turns out
to send differently simply produces no event -- never a wrong one -- and the
raw line is still in ``device_log_events`` and the archive.

The hotspot line carries no MAC, so a sign-in/out event can only ever be
linked to a session by IP (see ``GuestDeviceEventsReader``).
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .constants import TAG_HEX_LENGTH, TAG_PREFIX, Attribution


class GuestEventKind(StrEnum):
    """Wire contract with the customer UI (``deviceEvents`` presentation)."""

    IP_ASSIGNED = "ip_assigned"
    IP_RELEASED = "ip_released"
    ROUTER_SIGN_IN = "router_sign_in"
    ROUTER_SIGN_OUT = "router_sign_out"


@dataclass(frozen=True)
class GuestEvent:
    kind: GuestEventKind
    ip_address: str
    #: Upper-case ``AA:BB:CC:DD:EE:FF``. None for hotspot lines (they carry
    #: no MAC).
    mac_address: str | None
    #: Hotspot sign-out reason as RouterOS words it ("keepalive timeout").
    detail: str | None = None


_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"

# Our per-router prefix, wherever the identity left it: the parser now puts
# it in ``claimed_tag``, but rows stored before that fix (identity with a
# space) still carry "<rest of identity> wyfy-xxxxxxxx: " in the message.
_TAG_PREFIX_IN_MESSAGE = re.compile(
    rf"^(?:[^\s]+\s){{0,6}}?{re.escape(TAG_PREFIX)}[0-9a-f]{{{TAG_HEX_LENGTH}}}:?\s+"
)

_DHCP = re.compile(
    rf"^(?P<server>[\w.-]{{1,64}}) (?P<verb>assigned|deassigned) (?P<ip>{_IPV4}) "
    rf"(?P<prep>for|to|from) (?P<mac>{_MAC})(?: .*)?$"
)
# The user name is matched loosely (it is masked, and dropped), but the line
# must end exactly at "logged in" / "logged out[: reason]".
_HOTSPOT = re.compile(
    rf"^(?P<user>\S[^()]{{0,127}}?) \((?P<ip>{_IPV4})\): "
    r"(?P<what>logged in|logged out)(?:: (?P<reason>.{1,200}))?$"
)
#: A sign-out reason is shown only when it reads like RouterOS's own words
#: ("keepalive timeout", "user request"); anything else is dropped, never
#: shown raw.
_REASON = re.compile(r"^[a-z][a-z -]{0,63}$")

#: Which DHCP preposition goes with which verb. ``deassigned ... to`` is not a
#: RouterOS sentence; a line like that is not one of ours.
_DHCP_PREPOSITIONS = {
    "assigned": frozenset({"for", "to"}),
    "deassigned": frozenset({"for", "from"}),
}


def _valid_ipv4(text: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def message_body(message: str) -> str:
    """The message with any leading identity remainder and ``wyfy-`` tag
    removed."""
    match = _TAG_PREFIX_IN_MESSAGE.match(message)
    return message[match.end() :] if match else message


def parse_guest_event(message: str, *, topics: str | None = None) -> GuestEvent | None:
    """One guest-relevant event from a stored (masked) message, or None.

    ``topics`` is used only to *reject*: with ``remote-log-format=syslog``
    RouterOS sends no topic list, but when one is present and names neither
    ``dhcp`` nor ``hotspot`` the line is not one of these events, whatever
    its text says."""
    if topics:
        words = set(topics.split(","))
        if not words & {"dhcp", "hotspot"}:
            return None
    body = message_body(message.strip())

    dhcp = _DHCP.match(body)
    if dhcp:
        verb = dhcp.group("verb")
        if dhcp.group("prep") not in _DHCP_PREPOSITIONS[verb]:
            return None
        ip = _valid_ipv4(dhcp.group("ip"))
        if ip is None:
            return None
        return GuestEvent(
            kind=(
                GuestEventKind.IP_ASSIGNED
                if verb == "assigned"
                else GuestEventKind.IP_RELEASED
            ),
            ip_address=ip,
            mac_address=dhcp.group("mac").upper(),
        )

    hotspot = _HOTSPOT.match(body)
    if hotspot:
        ip = _valid_ipv4(hotspot.group("ip"))
        if ip is None:
            return None
        signed_in = hotspot.group("what") == "logged in"
        reason = hotspot.group("reason")
        if signed_in and reason:
            return None
        return GuestEvent(
            kind=(
                GuestEventKind.ROUTER_SIGN_IN
                if signed_in
                else GuestEventKind.ROUTER_SIGN_OUT
            ),
            ip_address=ip,
            mac_address=None,
            detail=(
                reason if not signed_in and reason and _REASON.match(reason) else None
            ),
        )
    return None


def guest_event_row(
    *,
    device_log_event_id: int,
    attribution: str,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
    router_id: uuid.UUID | None,
    received_at: datetime,
    device_time: datetime | None,
    topics: str | None,
    message: str,
) -> dict[str, Any] | None:
    """The ``guest_device_events`` row for one stored line, or None.

    Only lines attributed by tunnel IP with no tag disagreement count: a
    ``tag_mismatch`` line's router is in doubt, and an event shown against
    the wrong venue's guest is worse than no event."""
    if attribution != Attribution.TUNNEL_IP.value:
        return None
    if organization_id is None or location_id is None or router_id is None:
        return None
    event = parse_guest_event(message, topics=topics)
    if event is None:
        return None
    return {
        "device_log_event_id": device_log_event_id,
        "occurred_at": received_at,
        "device_time": device_time,
        "organization_id": organization_id,
        "location_id": location_id,
        "router_id": router_id,
        "kind": event.kind.value,
        "ip_address": event.ip_address,
        "mac_address": event.mac_address,
        "detail": event.detail,
    }

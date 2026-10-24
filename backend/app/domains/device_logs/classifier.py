"""Structured fields for one stored (already masked) device log line:
``category``, ``protocol``, ``src_ip``, ``dst_ip``, ``status`` and
``device_mac`` -- the columns behind the customer NetLogs table
(Timestamp | Device/Host | Source IP | Destination IP | Protocol | Status |
Message).

Same honesty rule as ``guest_events``: a field is filled only when the line
states it. A line this module does not recognise is ``other`` with every
other field NULL -- never a guessed status. The raw message is always kept.

Shapes recognised (RouterOS 7 with ``remote-log-format=syslog``; the body
is what follows the ``wyfy-<tag>:`` prefix):

=============  =============================================================
DHCP           ``<server> assigned <ip> for <mac> [<host>]`` (and
               ``deassigned``, and the RouterOS 6 ``to``/``from`` forms) --
               parsed by ``guest_events.parse_guest_event``, one parser for
               both consumers
Hotspot        ``<user> (<ip>): logged in`` / ``logged out[: <reason>]`` /
               ``login failed: <reason>``
Firewall       ``[<prefix> ]<chain>: in:<if> out:<if>, [connection-state:..
               ] [src-mac <mac>, ]proto TCP (SYN), <src>:<port>-><dst>:<port>
               [, NAT ...], len <n>`` (ICMP has no ports). Prefix ``WYFY-FW``
               is Wyfy's own log row above one of its drops: ``blocked``.
Wireless       ``<mac>@<iface>[:] connected[, ...]`` / ``disconnected[, ...]``
               (``wifi`` package and legacy ``wireless``)
System         ``user <name> logged in|out from <ip> via <svc>`` and
               ``login failure for user <name> from <ip> via <svc>``
=============  =============================================================

Provenance, stated honestly: as of 2026-10-18 only system/fetch lines have
been seen from the fleet, so the DHCP, hotspot, firewall and wireless shapes
come from RouterOS's documented output. A line the fleet sends differently is
stored as ``other`` (topic-derived category where a topic list was sent), not
mis-labelled.

DNS is not classified: DNS query logging is deliberately not collected.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .constants import LogCategory, LogStatus
from .guest_events import GuestEventKind, message_body, parse_guest_event


@dataclass(frozen=True)
class Classification:
    category: str
    protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    status: str | None = None
    device_mac: str | None = None


_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
#: An address as RouterOS prints it in a firewall line: IPv4 or [IPv6].
_ADDR = rf"(?:{_IPV4}|\[[0-9A-Fa-f:.]+\])"

_FIREWALL_HEAD = re.compile(
    r"^(?:(?P<prefix>.{0,64}?)\s)?(?P<chain>[\w-]{1,32}): in:\S* out:\S*"
)
_FIREWALL_PROTO = re.compile(
    rf"proto (?P<proto>[A-Za-z0-9-]{{1,16}})(?: \([^)]*\))?, "
    rf"(?P<src>{_ADDR})(?::(?P<sport>\d{{1,5}}))?->"
    rf"(?P<dst>{_ADDR})(?::(?P<dport>\d{{1,5}}))?"
)
_FIREWALL_SRC_MAC = re.compile(rf"src-mac (?P<mac>{_MAC})")
_BLOCK_WORDS = re.compile(r"drop|block|deny|denied|reject", re.IGNORECASE)
#: The prefix on Wyfy's own rate-limited log rows (gateway
#: ``mikrotik_firewall_logging.LOG_PREFIX``). Each sits directly above a
#: Wyfy drop/reject with the same matchers, so a line carrying it is a
#: packet that rule dropped -- "blocked" without needing a block word.
WYFY_FIREWALL_LOG_PREFIX = "WYFY-FW"
_ALLOW_WORDS = re.compile(r"accept|allow|permit", re.IGNORECASE)

_WIRELESS = re.compile(
    rf"^(?P<mac>{_MAC})@(?P<iface>[\w.-]{{1,32}}):? "
    r"(?P<what>connected|disconnected|reassociating|roamed)\b"
)

_HOTSPOT_FAILED = re.compile(
    rf"^\S[^()]{{0,127}}? \((?P<ip>{_IPV4})\): login failed(?::.*)?$"
)
_HOTSPOT_ANY = re.compile(rf"^\S[^()]{{0,127}}? \((?P<ip>{_IPV4})\): ")

_ADMIN_LOGIN = re.compile(
    rf"^user \S{{1,64}} logged (?P<what>in|out) from (?P<ip>{_ADDR}|\S+) "
    r"via (?P<via>[\w-]{1,16})"
)
_ADMIN_LOGIN_FAILURE = re.compile(
    rf"^login failure for user \S{{1,64}} from (?P<ip>{_ADDR}|\S+) "
    r"via (?P<via>[\w-]{1,16})"
)

#: Topic word -> category, for lines whose text is not one of the shapes
#: above but whose topic list (when RouterOS sends one) says what they are.
_TOPIC_CATEGORY: tuple[tuple[str, LogCategory], ...] = (
    ("firewall", LogCategory.FIREWALL),
    ("dhcp", LogCategory.DHCP),
    ("hotspot", LogCategory.HOTSPOT_AUTH),
    ("radius", LogCategory.RADIUS),
    ("wireless", LogCategory.WIRELESS),
    ("wifi", LogCategory.WIRELESS),
    ("caps", LogCategory.WIRELESS),
    ("system", LogCategory.SYSTEM),
    ("script", LogCategory.SYSTEM),
    ("account", LogCategory.SYSTEM),
)


def _ip(text: str | None) -> str | None:
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


def _firewall(body: str) -> Classification | None:
    head = _FIREWALL_HEAD.match(body)
    proto = _FIREWALL_PROTO.search(body)
    if head is None or proto is None:
        return None
    prefix = (head.group("prefix") or "").strip()
    words = f"{prefix} {head.group('chain')}"
    status: str | None = None
    if prefix == WYFY_FIREWALL_LOG_PREFIX or _BLOCK_WORDS.search(words):
        status = LogStatus.BLOCKED.value
    elif _ALLOW_WORDS.search(words):
        status = LogStatus.ALLOWED.value
    mac = _FIREWALL_SRC_MAC.search(body)
    return Classification(
        category=LogCategory.FIREWALL.value,
        protocol=proto.group("proto").upper()[:16],
        src_ip=_ip(proto.group("src")),
        dst_ip=_ip(proto.group("dst")),
        status=status,
        device_mac=mac.group("mac").upper() if mac else None,
    )


def _from_topics(topics: str | None) -> str:
    if topics:
        words = set(topics.split(","))
        for word, category in _TOPIC_CATEGORY:
            if word in words:
                return category.value
    return LogCategory.OTHER.value


#: QA-029 (founder-approved addition, 2026-10-24). A line whose syslog head
#: the parser could not read (e.g. a sender that space-pads the hour) is stored
#: whole as the message with NO topics, so the topic-driven rules never ran and
#: DHCP / wireless / system lines landed in "other". This reads the RouterOS
#: topics ("dhcp,info") out of the message's own head. Used ONLY on the path
#: that would otherwise return "other" with no topics, and only to reach the
#: dhcp, wireless or system categories -- every line classified today keeps
#: its exact result (test_device_logs_classify_corpus.py).
_UNPARSED_HEAD = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} +"
    r"\d{1,2}:\d{2}:\d{2} +)?"
    r"(?:\S+ +)?"
    r"(?:wyfy-[0-9a-f]{8}:? +)?"
    r"(?P<topics>[a-z0-9-]+(?:,[a-z0-9-]+)+) +(?P<rest>.+)$",
    re.DOTALL,
)
_UNPARSED_HEAD_CATEGORIES = frozenset(
    {LogCategory.DHCP.value, LogCategory.WIRELESS.value, LogCategory.SYSTEM.value}
)


def _from_unparsed_head(message: str) -> Classification | None:
    m = _UNPARSED_HEAD.match((message or "").strip())
    if not m:
        return None
    again = classify(m.group("rest"), topics=m.group("topics"), _fallback=False)
    return again if again.category in _UNPARSED_HEAD_CATEGORIES else None


def classify(
    message: str, *, topics: str | None = None, _fallback: bool = True
) -> Classification:
    """Structured fields for one stored message. Never raises."""
    body = message_body((message or "").strip())

    guest = parse_guest_event(message, topics=topics)
    if guest is not None:
        if guest.kind in (GuestEventKind.IP_ASSIGNED, GuestEventKind.IP_RELEASED):
            return Classification(
                category=LogCategory.DHCP.value,
                protocol="DHCP",
                dst_ip=guest.ip_address,
                status=(
                    LogStatus.SUCCESS.value
                    if guest.kind == GuestEventKind.IP_ASSIGNED
                    else LogStatus.RELEASED.value
                ),
                device_mac=guest.mac_address,
            )
        return Classification(
            category=LogCategory.HOTSPOT_AUTH.value,
            protocol="HOTSPOT",
            src_ip=guest.ip_address,
            status=(
                LogStatus.SUCCESS.value
                if guest.kind == GuestEventKind.ROUTER_SIGN_IN
                else LogStatus.DISCONNECTED.value
            ),
        )

    fw = _firewall(body)
    if fw is not None:
        return fw

    wireless = _WIRELESS.match(body)
    if wireless:
        what = wireless.group("what")
        return Classification(
            category=LogCategory.WIRELESS.value,
            protocol="WLAN",
            status=(
                LogStatus.CONNECTED.value
                if what == "connected"
                else LogStatus.DISCONNECTED.value
                if what == "disconnected"
                else None
            ),
            device_mac=wireless.group("mac").upper(),
        )

    failed = _HOTSPOT_FAILED.match(body)
    if failed:
        return Classification(
            category=LogCategory.HOTSPOT_AUTH.value,
            protocol="HOTSPOT",
            src_ip=_ip(failed.group("ip")),
            status=LogStatus.FAILURE.value,
        )

    admin = _ADMIN_LOGIN.match(body)
    if admin:
        return Classification(
            category=LogCategory.SYSTEM.value,
            protocol=admin.group("via").upper(),
            src_ip=_ip(admin.group("ip")),
            status=(
                LogStatus.SUCCESS.value
                if admin.group("what") == "in"
                else LogStatus.DISCONNECTED.value
            ),
        )
    admin_failed = _ADMIN_LOGIN_FAILURE.match(body)
    if admin_failed:
        return Classification(
            category=LogCategory.SYSTEM.value,
            protocol=admin_failed.group("via").upper(),
            src_ip=_ip(admin_failed.group("ip")),
            status=LogStatus.FAILURE.value,
        )

    category = _from_topics(topics)
    if category == LogCategory.HOTSPOT_AUTH.value:
        any_hotspot = _HOTSPOT_ANY.match(body)
        return Classification(
            category=category,
            protocol="HOTSPOT",
            src_ip=_ip(any_hotspot.group("ip")) if any_hotspot else None,
        )
    if category == LogCategory.OTHER.value and not topics and _fallback:
        recovered = _from_unparsed_head(message)
        if recovered is not None:
            return recovered
    return Classification(category=category)


def classification_columns(
    message: str, *, topics: str | None
) -> dict[str, str | None]:
    """The six column values, ready for an insert/update."""
    c = classify(message, topics=topics)
    return {
        "category": c.category,
        "protocol": c.protocol,
        "src_ip": c.src_ip,
        "dst_ip": c.dst_ip,
        "status": c.status,
        "device_mac": c.device_mac,
    }


#: Short human headline for the Message column, derived at read time from
#: category + status so it can change without a backfill. None: show the
#: raw message.
_SUMMARIES: dict[tuple[str, str | None], str] = {
    ("dhcp", "success"): "IP assigned",
    ("dhcp", "released"): "IP released",
    ("hotspot_auth", "success"): "Guest signed in",
    ("hotspot_auth", "disconnected"): "Guest signed out",
    ("hotspot_auth", "failure"): "Guest sign-in failed",
    ("radius", "accept"): "RADIUS accepted",
    ("radius", "reject"): "RADIUS rejected",
    ("firewall", "blocked"): "Traffic denied",
    ("firewall", "allowed"): "Traffic allowed",
    ("firewall", None): "Firewall match",
    ("wireless", "connected"): "Device connected to WiFi",
    ("wireless", "disconnected"): "Device disconnected from WiFi",
    ("system", "success"): "Admin logged in",
    ("system", "disconnected"): "Admin logged out",
    ("system", "failure"): "Admin login failed",
}


def summary_for(category: str | None, status: str | None) -> str | None:
    if category is None:
        return None
    return _SUMMARIES.get((category, status))

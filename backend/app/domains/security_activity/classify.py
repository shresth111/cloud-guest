"""Security activity: which router rows belong to which protection, and the
plain sentence a venue owner reads for each.

Pure -- no I/O. ``classify_counter_rows`` takes the rows a read-only 8728
``print`` of ``/ip/firewall/filter`` and ``/ip/firewall/nat`` returned and
picks out the ones this platform owns, by comment. A row it does not
recognise is ignored, never guessed at: a venue's own hand-written rule is
not one of *our* protections, and counting it as one would claim credit for
something we did not do.

## What the numbers are

RouterOS keeps a ``packets``/``bytes`` counter on every filter and NAT row,
cumulative since the row was added or the router last rebooted. The
collector stores hourly deltas of those. They count **packets**, not
attempts: one refused connection is typically one to three packets (a TCP
client retries its SYN), one blocked HTTPS site is about one ClientHello per
connection. The UI says "attempts" in its sentences and states this in its
footnote rather than dividing by a guess.

## What cannot be counted here

* ``/ip dns static`` rows (the DNS half of a website block, the canary
  domains, DoH hostnames) have **no** hit counter in RouterOS. Only the
  ``tls-host`` half of a website block is counted.
* ``/ip hotspot ip-binding type=blocked`` (device blocks) has no counter
  either; device blocks are reported from the database as a count of
  devices, not hits.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from wyfy_device_gateway.mikrotik_dns_filtering import (
    LAYER_CANARY_DOMAINS,
    LAYER_DOH_HOSTNAMES,
    LAYER_DOH_IP_LIST,
    LAYER_ENCRYPTED_DNS_PORTS,
    LAYER_PLAIN_DNS_REDIRECT,
    LAYER_VPN_BLOCK,
)
from wyfy_device_gateway.mikrotik_dns_filtering import (
    _layer_of_comment as dns_bypass_layer_of_comment,
)
from wyfy_device_gateway.mikrotik_firewall import (
    FLOOD_LIMIT_COMMENT,
    RULE_MARKER_PREFIX,
)
from wyfy_device_gateway.mikrotik_guest_isolation import (
    GUARD_COMMENT as GUEST_ISOLATION_GUARD_COMMENT,
)

__all__ = [
    "CounterReading",
    "Protection",
    "PROTECTION_LABELS",
    "classify_counter_rows",
    "protection_sentence",
]


class Protection(StrEnum):
    WEBSITE_BLOCK = "website_block"
    ADDRESS_BLOCK = "address_block"
    PRIVATE_NETWORK = "private_network"
    GUEST_ISOLATION = "guest_isolation"
    ACCESS_RULE = "access_rule"
    FLOOD_LIMIT = "flood_limit"
    DNS_BYPASS = "dns_bypass"
    DNS_REDIRECT = "dns_redirect"
    VPN_BLOCK = "vpn_block"
    # Not router counters -- reported from other sources by the service.
    DEVICE_BLOCK = "device_block"
    CLOUDFLARE_DNS = "cloudflare_dns"


PROTECTION_LABELS: dict[Protection, str] = {
    Protection.WEBSITE_BLOCK: "Blocked websites",
    Protection.ADDRESS_BLOCK: "Blocked IP addresses",
    Protection.PRIVATE_NETWORK: "Keep guests off your private network",
    Protection.GUEST_ISOLATION: "Guests can't see each other",
    Protection.ACCESS_RULE: "Your firewall rules",
    Protection.FLOOD_LIMIT: "Connection flood limit",
    Protection.DNS_BYPASS: "Filter bypass protection",
    Protection.DNS_REDIRECT: "DNS kept on your filter",
    Protection.VPN_BLOCK: "VPN blocking",
    Protection.DEVICE_BLOCK: "Blocked devices",
    Protection.CLOUDFLARE_DNS: "Website category filtering (Cloudflare)",
}

_SENTENCES: dict[Protection, tuple[str, str]] = {
    # (sentence with a count, sentence for zero)
    Protection.WEBSITE_BLOCK: (
        "Stopped {n} attempts to open websites you blocked.",
        "No one tried to open a website you blocked.",
    ),
    Protection.ADDRESS_BLOCK: (
        "Stopped {n} attempts to reach IP addresses you blocked.",
        "No one tried to reach an IP address you blocked.",
    ),
    Protection.PRIVATE_NETWORK: (
        "Stopped {n} attempts by guests to reach your private network.",
        "No guest tried to reach your private network.",
    ),
    Protection.GUEST_ISOLATION: (
        "Stopped {n} attempts by guests to reach each other's devices.",
        "No guest tried to reach another guest's device.",
    ),
    Protection.ACCESS_RULE: (
        "Your firewall rules blocked {n} connection attempts.",
        "Your firewall rules did not need to block anything.",
    ),
    Protection.FLOOD_LIMIT: (
        "Cut off {n} extra connections from devices opening too many at once.",
        "No guest device opened too many connections at once.",
    ),
    Protection.DNS_BYPASS: (
        "Stopped {n} attempts to get around your website filtering.",
        "No one tried to get around your website filtering.",
    ),
    Protection.DNS_REDIRECT: (
        "Sent {n} outside DNS lookups back through your filter.",
        "No device tried to use its own DNS server.",
    ),
    Protection.VPN_BLOCK: (
        "Stopped {n} attempts to use a VPN to get around your filters.",
        "No one tried to use a VPN to get around your filters.",
    ),
    Protection.DEVICE_BLOCK: (
        "{n} devices are blocked from your WiFi right now.",
        "No device is blocked from your WiFi right now.",
    ),
    Protection.CLOUDFLARE_DNS: (
        "Cloudflare refused {n} lookups of sites in categories you filter.",
        "Cloudflare did not need to refuse any lookups.",
    ),
}


def protection_sentence(protection: Protection, count: int) -> str:
    with_count, zero = _SENTENCES[protection]
    return with_count.format(n=f"{count:,}") if count > 0 else zero


_DNS_LAYER_LABELS: dict[str, str] = {
    LAYER_ENCRYPTED_DNS_PORTS: "Encrypted DNS (DoT/DoQ) blocked",
    LAYER_DOH_IP_LIST: "Known DNS-over-HTTPS servers blocked",
    LAYER_DOH_HOSTNAMES: "DNS-over-HTTPS by name blocked",
    LAYER_PLAIN_DNS_REDIRECT: "Outside DNS redirected to your filter",
    LAYER_VPN_BLOCK: "VPN protocols blocked",
    LAYER_CANARY_DOMAINS: "Browser auto-DoH switched off",
}

#: Provisioning-time rows (the router setup script) that stop guests using a
#: DNS server of their own. Counted with bypass protection.
_SETUP_DNS_BYPASS_COMMENTS: dict[str, str] = {
    "cloudguest-fw-block-wan-dns": "Outside DNS (UDP) blocked",
    "cloudguest-fw-block-wan-dns-tcp": "Outside DNS (TCP) blocked",
    "cloudguest-block-dot-udp": "Encrypted DNS before sign-in blocked",
}


_CONTENT_FILTER_ADDRESS_DROP = "Wyfy Guest content filtering: block listed addresses"
_CONTENT_FILTER_ROW = re.compile(
    r"^WyfyGuest content filter "
    r"(?P<rule_id>[0-9a-fA-F-]{36})"
    r" \((?:https|https subdomains)\): ?(?P<label>.*)$"
)
_FW_RULE_ROW = re.compile(
    "^" + re.escape(RULE_MARKER_PREFIX) + r"(?P<rule_id>[0-9a-f-]{36})$"
)

_BLOCKING_ACTIONS = frozenset({"drop", "reject", "tarpit"})


@dataclass(frozen=True, slots=True)
class CounterReading:
    """One counted router row, classified.

    ``rule_key`` is the row's comment (stable across reads); ``ref_id`` is
    the platform row it was written from, when the comment names one, so
    the service can show the venue's own name for it."""

    protection: Protection
    rule_key: str
    label: str
    packets: int
    bytes: int
    ref_id: str | None = None


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _is_disabled(row: dict[str, Any]) -> bool:
    return str(row.get("disabled", "false")).lower() in {"true", "yes"}


def _targets_private_network(dst: str | None) -> bool:
    """True when every destination in ``dst`` is a private (RFC 1918 /
    unique-local) range -- the shape of "keep guests off your private
    network". A rule with no destination, or any public one, is a general
    access rule, not this protection."""
    if not dst:
        return False
    text = dst.strip().lstrip("!")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return network.is_private and not network.is_loopback and not network.is_link_local


def classify_counter_rows(
    filter_rows: list[dict[str, Any]],
    nat_rows: list[dict[str, Any]] | None = None,
) -> list[CounterReading]:
    """Every platform-owned, enabled, blocking (or redirecting) row with
    readable counters, classified into a protection. Rows without
    ``packets``/``bytes`` are skipped rather than read as zero."""
    out: list[CounterReading] = []

    def add(
        row: dict[str, Any],
        protection: Protection,
        label: str,
        ref_id: str | None = None,
    ) -> None:
        packets = _as_int(row.get("packets"))
        size = _as_int(row.get("bytes"))
        if packets is None or size is None:
            return
        out.append(
            CounterReading(
                protection=protection,
                rule_key=str(row.get("comment") or "")[:160],
                label=label[:255],
                packets=packets,
                bytes=size,
                ref_id=ref_id,
            )
        )

    for row in filter_rows:
        comment = str(row.get("comment") or "")
        if not comment or _is_disabled(row):
            continue
        action = str(row.get("action") or "").lower()
        if comment == FLOOD_LIMIT_COMMENT:
            add(row, Protection.FLOOD_LIMIT, "Connection flood limit")
            continue
        if comment == GUEST_ISOLATION_GUARD_COMMENT:
            add(row, Protection.GUEST_ISOLATION, "Guest-to-guest traffic blocked")
            continue
        if comment == _CONTENT_FILTER_ADDRESS_DROP:
            add(row, Protection.ADDRESS_BLOCK, "Blocked IP addresses")
            continue
        if comment in _SETUP_DNS_BYPASS_COMMENTS:
            add(row, Protection.DNS_BYPASS, _SETUP_DNS_BYPASS_COMMENTS[comment])
            continue
        match = _CONTENT_FILTER_ROW.match(comment)
        if match:
            add(
                row,
                Protection.WEBSITE_BLOCK,
                match.group("label") or str(row.get("tls-host") or "Blocked website"),
                ref_id=match.group("rule_id").lower(),
            )
            continue
        match = _FW_RULE_ROW.match(comment)
        if match:
            if action not in _BLOCKING_ACTIONS:
                continue  # an allow rule protects nothing; its hits are not blocks
            protection = (
                Protection.PRIVATE_NETWORK
                if _targets_private_network(row.get("dst-address"))
                else Protection.ACCESS_RULE
            )
            add(row, protection, "Firewall rule", ref_id=match.group("rule_id"))
            continue
        layer = dns_bypass_layer_of_comment(comment)
        if layer is not None:
            protection = (
                Protection.VPN_BLOCK
                if layer == LAYER_VPN_BLOCK
                else Protection.DNS_BYPASS
            )
            add(row, protection, _DNS_LAYER_LABELS.get(layer, layer))

    for row in nat_rows or []:
        comment = str(row.get("comment") or "")
        if not comment or _is_disabled(row):
            continue
        if dns_bypass_layer_of_comment(comment) == LAYER_PLAIN_DNS_REDIRECT:
            add(
                row,
                Protection.DNS_REDIRECT,
                _DNS_LAYER_LABELS[LAYER_PLAIN_DNS_REDIRECT]
                + (" (TCP)" if comment.endswith("tcp") else " (UDP)"),
            )
    return out

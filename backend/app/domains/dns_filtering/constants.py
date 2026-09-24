"""Constants and pure helpers for Cloudflare Gateway DNS filtering."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from enum import StrEnum

#: The venue-facing name used in refusals (controller-managed venues,
#: unsupported vendors). A noun phrase in the console's own vocabulary.
FEATURE_NAME = "Category filtering"

#: Cloudflare's "Security threats" parent category. Its subcategories
#: (Malware 117, Phishing 131, Command and Control & Botnet 80, ...) are
#: matched with ``dns.security_category``; every other id with
#: ``dns.content_category``. From Cloudflare's published domain-category
#: table; the live catalogue is consulted first and this is only the anchor.
SECURITY_THREATS_CATEGORY_ID = 21

#: Classes Cloudflare will not let a policy add (``removalPending``) or
#: block (``noBlock``). Refused up front rather than surfaced as a failed
#: Cloudflare sync.
UNSELECTABLE_CATEGORY_CLASSES = frozenset({"noBlock", "removalPending"})

#: How long the category catalogue is cached in-process. The catalogue
#: changes on Cloudflare's schedule, not ours; an hour keeps the category
#: picker from calling Cloudflare on every page load.
CATEGORY_CACHE_TTL_SECONDS = 3600

#: Gateway DNS rule precedence for our profile rules starts here, leaving
#: room below for anything an operator adds by hand in the Cloudflare
#: dashboard (lower precedence value = evaluated first).
RULE_PRECEDENCE_BASE = 10_000


#: Cloudflare Gateway "Anonymizer" -- a subcategory of Security threats (21),
#: "Sites that allow users to surf the Internet anonymously", per Cloudflare's
#: published domain-category table (developers.cloudflare.com/cloudflare-one/
#: traffic-policies/domain-categories/). Added to a router's Gateway profile
#: only while that router's VPN-blocking layer is on, and only if the live
#: catalogue still lists it. The table has no "VPN" or "Proxy" category.
ANONYMIZER_CATEGORY_ID = 68


class BypassLayer(StrEnum):
    """The individually switchable DNS-bypass layers. Values are the device
    gateway's (``wyfy_device_gateway.mikrotik_dns_filtering.BYPASS_LAYERS``);
    a test pins the two together."""

    CANARY_DOMAINS = "canary_domains"
    ENCRYPTED_DNS_PORTS = "encrypted_dns_ports"
    DOH_IP_LIST = "doh_ip_list"
    DOH_HOSTNAMES = "doh_hostnames"
    PLAIN_DNS_REDIRECT = "plain_dns_redirect"
    VPN_BLOCK = "vpn_block"


#: ``{"enabled": true}`` with no layer list means these. VPN blocking is
#: never implied: hotel and business guests use corporate VPNs.
DEFAULT_BYPASS_LAYERS: frozenset[str] = frozenset(
    layer.value for layer in BypassLayer if layer is not BypassLayer.VPN_BLOCK
)

#: Layers whose device state depends on the synced public DoH lists, so a
#: list refresh has to be pushed to the router.
LIST_BACKED_LAYERS: frozenset[str] = frozenset(
    {BypassLayer.DOH_IP_LIST.value, BypassLayer.DOH_HOSTNAMES.value}
)

#: Well-known DoH hostnames: sinkholed (NXDOMAIN) whatever the synced list
#: says, and the only names that get a per-packet ``tls-host`` drop. Every
#: one was checked present in dibdot/DoH-IP-blocklists ``doh-domains.txt``
#: on 2026-09-24. Kept short on purpose: each ``tls-host`` rule is a
#: per-packet match on small hardware.
CURATED_DOH_HOSTNAMES: tuple[str, ...] = (
    "dns.google",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "dns.adguard-dns.com",
    "dns.adguard.com",
    "family.adguard-dns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "doh.mullvad.net",
    "dns.mullvad.net",
    "dns.controld.com",
    "freedns.controld.com",
    "doh.dns.sb",
    "dns.alidns.com",
    "doh.pub",
    "dns.twnic.tw",
    "doh.libredns.gr",
    "dns0.eu",
)


class BlocklistKind(StrEnum):
    """One platform-wide row per kind in ``dns_bypass_blocklists``."""

    DOH_IPV4 = "doh_ipv4"
    DOH_IPV6 = "doh_ipv6"
    DOH_DOMAINS = "doh_domains"


class BlocklistRefreshStatus(StrEnum):
    OK = "ok"
    #: Fetched, but refused by validation (shrank too far, over the cap,
    #: empty). The last good list is kept.
    REFUSED = "refused"
    #: Could not fetch. The last good list is kept.
    ERROR = "error"


#: Celery. The coordinator (Beat) refreshes the platform lists -- outbound
#: HTTPS to GitHub, no device I/O -- then fans out one leaf per opted-in
#: router; the leaf is the RouterOS round trip and runs on the device-I/O
#: queue.
TASK_REFRESH_DNS_BYPASS_BLOCKLISTS = (
    "app.domains.dns_filtering.tasks.refresh_dns_bypass_blocklists"
)
TASK_PUSH_DNS_BYPASS_LISTS_FOR_ROUTER = (
    "app.domains.dns_filtering.tasks.push_dns_bypass_lists_for_router"
)
#: Six hours. The source regenerates its address files several times a day
#: and its hostname list about monthly; a DoH server that appeared this
#: morning is not an emergency, and every tick that finds a change dials
#: every opted-in router.
DNS_BYPASS_REFRESH_INTERVAL_SECONDS = 21_600.0
DNS_BYPASS_REFRESH_LOCK_REDIS_KEY = "dns_filtering:bypass_list_refresh:lock"
DNS_BYPASS_REFRESH_LOCK_TTL_SECONDS = 600


class RouterFilteringState(StrEnum):
    """Where one router is in its Cloudflare DNS lifecycle."""

    #: The router's profile location exists (or is being created); the
    #: router has not yet been switched successfully.
    PENDING = "pending"
    #: The router resolves through Gateway, probe passed.
    ACTIVE = "active"
    #: The first switch failed. ``device_push_error`` says why and whether the
    #: rollback read back clean. (A failed *move* between two profiles of a
    #: router that was already active, rolled back clean, stays ACTIVE on its
    #: previous profile with ``device_push_status=failed``.)
    FAILED = "failed"
    #: Switched off; the router's own DNS settings were restored.
    DISABLED = "disabled"


class DevicePushStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


class ProfileSyncStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


class BypassHardeningStatus(StrEnum):
    OFF = "off"
    ACTIVE = "active"
    FAILED = "failed"


def canonical_category_ids(ids: Iterable[int]) -> list[int]:
    """Sorted, de-duplicated. Two venues choosing the same set in a different
    order are the same profile."""
    return sorted({int(i) for i in ids})


def profile_fingerprint(ids: Iterable[int]) -> str:
    """The profile key: sha256 of the canonical id list. Stable across
    processes (unlike ``hash``)."""
    canonical = ",".join(str(i) for i in canonical_category_ids(ids))
    return hashlib.sha256(canonical.encode()).hexdigest()


def gateway_location_name(profile_id: uuid.UUID) -> str:
    """The Cloudflare location name for a category profile.

    Locations are allocated **per profile** (one per distinct category set),
    not per router, so the name is keyed on our profile UUID and nothing
    else. A profile is platform-owned and holds only category ids; the name
    carries no organization, venue or router name, so a location shared by
    venues of different tenants reveals nothing about any of them, and a
    location found by name after a crashed create is provably ours.
    """
    return f"wyfy-profile-{profile_id}"


def gateway_rule_name(profile_id: uuid.UUID) -> str:
    """Same key as the location, same reason: nothing tenant-derived."""
    return f"wyfy-profile-{profile_id}"


def category_distance(a: Iterable[int], b: Iterable[int]) -> int:
    """How far two category sets are apart: the size of their symmetric
    difference. Used only to suggest the nearest existing profile when a new
    distinct set would exceed the location cap."""
    return len(set(a) ^ set(b))


def doh_url(doh_subdomain: str) -> str:
    return f"https://{doh_subdomain}.cloudflare-gateway.com/dns-query"


def build_rule_traffic(
    *,
    content_ids: Iterable[int],
    security_ids: Iterable[int],
    location_ids: Iterable[str],
) -> str:
    """The Gateway wirefilter expression for one profile.

    ``(any(dns.content_category[*] in {..}) or any(dns.security_category[*]
    in {..})) and dns.location in {"<id>" ...}`` -- selector syntax from
    Cloudflare's DNS policy docs. Sorted throughout so an unchanged profile
    produces a byte-identical expression and a re-sync is a no-op diff.
    """
    content = canonical_category_ids(content_ids)
    security = canonical_category_ids(security_ids)
    locations = sorted(set(location_ids))
    if not locations:
        raise ValueError("a profile rule needs at least one location")
    if not content and not security:
        raise ValueError("a profile rule needs at least one category")
    parts: list[str] = []
    if content:
        parts.append(
            "any(dns.content_category[*] in {" + " ".join(map(str, content)) + "})"
        )
    if security:
        parts.append(
            "any(dns.security_category[*] in {" + " ".join(map(str, security)) + "})"
        )
    categories = parts[0] if len(parts) == 1 else "(" + " or ".join(parts) + ")"
    location_set = " ".join(f'"{loc}"' for loc in locations)
    return f"{categories} and dns.location in {{{location_set}}}"


__all__ = [
    "ANONYMIZER_CATEGORY_ID",
    "BlocklistKind",
    "BlocklistRefreshStatus",
    "BypassHardeningStatus",
    "BypassLayer",
    "CURATED_DOH_HOSTNAMES",
    "DEFAULT_BYPASS_LAYERS",
    "DNS_BYPASS_REFRESH_INTERVAL_SECONDS",
    "DNS_BYPASS_REFRESH_LOCK_REDIS_KEY",
    "DNS_BYPASS_REFRESH_LOCK_TTL_SECONDS",
    "TASK_PUSH_DNS_BYPASS_LISTS_FOR_ROUTER",
    "TASK_REFRESH_DNS_BYPASS_BLOCKLISTS",
    "LIST_BACKED_LAYERS",
    "CATEGORY_CACHE_TTL_SECONDS",
    "DevicePushStatus",
    "FEATURE_NAME",
    "ProfileSyncStatus",
    "RULE_PRECEDENCE_BASE",
    "RouterFilteringState",
    "SECURITY_THREATS_CATEGORY_ID",
    "UNSELECTABLE_CATEGORY_CLASSES",
    "build_rule_traffic",
    "canonical_category_ids",
    "category_distance",
    "doh_url",
    "gateway_location_name",
    "gateway_rule_name",
    "profile_fingerprint",
]

"""Enumerations, the security-score model, and the honest capability matrix
for the Security domain.

## What this module is, and deliberately is not

``app.domains.security`` is a **read-only** aggregation domain. It owns no
tables and writes nothing, to any database and to no device. It exists to
answer one question honestly: *what is this venue's security posture, and
which security features can this platform actually enforce for it?*

It owns no tables on purpose. Every number it reports is already stored by
the domain that produced it -- ``routers``/``router_health_snapshots`` for
fleet health, ``content_filter_rules`` for blocking, ``device_access_rules``
for blocked devices, ``firewall_rules`` for rules,
``router_rogue_dhcp_statuses`` for the DHCP guard, ``alerts`` for alert
pressure. A second copy of any of those numbers would be a number that
can disagree with its own source, and this codebase has already paid for that
class of bug once -- see ``app.domains.content_filtering.device_adapters``
module docstring, where a dashboard reported "blocked" for a rule that had
never reached a device.

## The score is a diagnostic of *our own configuration*, not a threat score

Nothing here can observe an attack. So the score is defined as the absence of
known-good hygiene, computed only from facts this platform already stores and
can re-derive: whether the fleet is reporting, whether enabled blocks actually
reached a device, whether the DHCP guard is on, whether anything is already
alerting.

## What this domain never shows a venue

The platform's management tunnel (WireGuard, hub to router) is not a venue's
security control and is not something a venue can act on; it is this
platform's own plumbing. It is deliberately absent from both the score and the
capability matrix, because everything here is served to the customer
dashboard. Tunnel health belongs to the Master console and the backend's own
monitoring, which already read ``wireguard_peers`` directly.

That definition is what makes the number honest, and it is also what bounds
it -- see ``SCORE_FACTOR_WEIGHTS``'s own comment. A venue that has done
nothing wrong scores 100 of 100; it does not score "secure".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

# The score is presented as "out of 100" and is a pure subtraction from a
# clean slate, so the maximum is also the starting value.
SECURITY_SCORE_MAX = 100

# A venue with no agent-managed gateway at all has no posture to score.
# Returning 100 for it would be the worst kind of lie -- an empty venue
# reading as a hardened one. See SecurityOverviewService.build_score.
MIN_ROUTERS_FOR_SCORE = 1


class SecurityScoreBand(StrEnum):
    """The band a score falls into, for the dashboard's colour/label.

    Thresholds are exposed rather than inlined so the frontend and the
    documentation cannot drift from what the API actually returns."""

    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


SCORE_BAND_THRESHOLDS: tuple[tuple[int, SecurityScoreBand], ...] = (
    (90, SecurityScoreBand.EXCELLENT),
    (75, SecurityScoreBand.GOOD),
    (50, SecurityScoreBand.FAIR),
    (0, SecurityScoreBand.POOR),
)


def score_band_for(score: int) -> SecurityScoreBand:
    """The band for ``score`` -- highest threshold that does not exceed it."""
    for threshold, band in SCORE_BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return SecurityScoreBand.POOR


class ScoreFactorKey(StrEnum):
    """One term in the score. Each is a real, already-stored fact."""

    FLEET_REPORTING = "fleet_reporting"
    BLOCK_PUSH_INTEGRITY = "block_push_integrity"
    ROGUE_DHCP_GUARD = "rogue_dhcp_guard"
    ALERT_PRESSURE = "alert_pressure"


#: Per-failure penalty, and the cap that stops one bad factor from consuming
#: the whole score. Both are module constants rather than tunables: a score
#: whose weights are configurable is a score nobody can reproduce, and this
#: number is meant to be explainable to a venue owner, not tuned.
#:
#: The caps matter more than the weights. Without them, a single venue with
#: 400 stale DHCP records scores 0 and the number stops distinguishing
#: between "one thing is wrong" and "everything is wrong".
SCORE_FACTOR_WEIGHTS: dict[ScoreFactorKey, tuple[int, int]] = {
    # (per-occurrence penalty as a share of affected routers, max penalty)
    ScoreFactorKey.FLEET_REPORTING: (60, 40),
    ScoreFactorKey.BLOCK_PUSH_INTEGRITY: (30, 25),
    ScoreFactorKey.ROGUE_DHCP_GUARD: (10, 15),
    ScoreFactorKey.ALERT_PRESSURE: (5, 10),
}

# There is deliberately no staleness threshold here. The platform's own single
# source of truth for "this gateway has stopped reporting" is
# ``app.domains.monitoring.constants.ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``,
# and a second threshold in this domain would be a second answer to the same
# question -- the class of drift ``app.common.device_push``'s module docstring
# was written to stop. ``SecurityOverviewService`` imports that constant rather
# than defining one.


class SecurityAvailability(StrEnum):
    """Whether a security feature can be honoured, or only displayed.

    This is the enum the whole module exists to make enumerable. The brief's
    own requirement is that a feature must not be presented as supported
    merely because a dashboard can render it, and the separation it asks for
    (available now / requires additional technology / future) is exactly
    these three values."""

    #: Enforceable on the fleet this platform already manages, today.
    AVAILABLE = "available"
    #: Real, but needs something this platform does not have yet -- a
    #: maintained category database, a threat feed, DPI, a DNS filtering
    #: provider, or simply the device writer that would put the rule on a
    #: router. Usable only after that dependency exists. Where the mechanism
    #: is known, ``enforcement`` names it prefixed ``"Planned: "``, so the
    #: API never presents an intended mechanism as a working one.
    REQUIRES_ADDITIONAL_TECHNOLOGY = "requires_additional_technology"
    #: Not honestly deliverable on the current architecture at all. Rendered
    #: so the gap is visible and explained rather than silently absent.
    NOT_SUPPORTED = "not_supported"


@dataclass(frozen=True, slots=True)
class SecurityFeature:
    """One row of the capability matrix.

    ``enforcement`` names the real mechanism where one exists, because
    "available" without a mechanism is the claim this module refuses to make.
    """

    key: str
    label: str
    availability: SecurityAvailability
    enforcement: str | None
    detail: str


#: The honest matrix. Kept as data, not prose, so the API returns it, the
#: dashboard renders it, and a test can assert the exclusions stay excluded.
#:
#: Every ``AVAILABLE`` entry here is enforced by something that already ships
#: in this codebase, and ``tests/unit/test_security.py`` holds the map from
#: each one to the function that writes it to a router -- so an entry cannot
#: be promoted to ``AVAILABLE`` without naming a writer that imports.
#:
#: Every exclusion states what is missing, not that the feature is hard --
#: a distinction that matters when someone later asks "why can't I block
#: Instagram?".
SECURITY_FEATURES: tuple[SecurityFeature, ...] = (
    SecurityFeature(
        key="zone_to_zone_firewall",
        label="Zone-to-zone firewall",
        availability=SecurityAvailability.AVAILABLE,
        enforcement=(
            "/ip firewall filter chain=forward inside the platform's sentinel "
            "band, pushed over 8728 in priority order"
        ),
        detail=(
            "Routed traffic between zones that have their own VLAN interface "
            "and subnet, written as source/destination address rules. A "
            "router must first have its firewall band placed from the "
            "platform console; until then a push is refused rather than "
            "guessed. Traffic switched within one subnet never reaches "
            "chain=forward and is out of scope, and a block must name a "
            "source or destination address."
        ),
    ),
    SecurityFeature(
        key="domain_blocking_dns",
        label="Domain blocking (DNS)",
        availability=SecurityAvailability.AVAILABLE,
        enforcement="/ip dns static sinkhole, pushed over 8728",
        detail=(
            "Applies to clients that use this router as their resolver. A "
            "client with its own DNS settings, or DNS-over-HTTPS once "
            "authenticated, is not covered."
        ),
    ),
    SecurityFeature(
        key="domain_blocking_sni",
        label="Domain blocking (HTTPS hostname)",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement=(
            "Planned: /ip firewall filter tls-host (RouterOS 6.41+), pushed "
            "over 8728"
        ),
        detail=(
            "No code writes a tls-host rule to a router yet; website "
            "blocking today is the DNS sinkhole only. Once built it would "
            "match the hostname in the TLS handshake without inspecting "
            "traffic, lose coverage when Encrypted Client Hello negotiates, "
            "and see nothing for QUIC, plain HTTP or a VPN."
        ),
    ),
    SecurityFeature(
        key="ip_and_cidr_blocking",
        label="IP and CIDR blocking",
        availability=SecurityAvailability.AVAILABLE,
        enforcement="/ip firewall address-list plus one positioned drop rule",
        detail=(
            "Inbound and outbound both work for literal addresses. It is not "
            "a substitute for domain blocking: services behind rotating CDN "
            "addresses cannot be maintained as an IP list."
        ),
    ),
    SecurityFeature(
        key="device_isolation",
        label="Device isolation and blocking",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement=(
            "Planned: /ip hotspot ip-binding type=blocked for known hardware; "
            "address-list drop for an address"
        ),
        detail=(
            "Blocking a guest today ends their live session and refuses the "
            "next sign-in; nothing writes a durable per-device block "
            "(ip-binding) to a router yet. When built it would be durable "
            "for enrolled hardware; for anonymous guests, MAC randomisation "
            "means a block is per-identity, and an IP-keyed block lapses "
            "when the DHCP lease changes."
        ),
    ),
    SecurityFeature(
        key="rogue_dhcp_detection",
        label="Rogue DHCP detection",
        availability=SecurityAvailability.AVAILABLE,
        enforcement="/ip dhcp-server alert, with state recorded per router interface",
        detail="Already implemented and already monitored.",
    ),
    SecurityFeature(
        key="connection_flood_protection",
        label="Connection and brute-force limits",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement="Planned: /ip firewall filter connection-limit and dst-limit",
        detail=(
            "No code writes a connection-limit rule to a router yet. When "
            "built it is threshold-based, so it reduces rather than "
            "eliminates the exposure, and it can drop legitimate bursts "
            "under a tight limit."
        ),
    ),
    SecurityFeature(
        key="web_category_filtering",
        label="Web category filtering",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement=None,
        detail=(
            "Needs a maintained domain-to-category database and a resolver "
            "that applies it. RouterOS provides neither, and this platform "
            "does not run a filtering resolver. A DNS filtering provider "
            "would supply both."
        ),
    ),
    SecurityFeature(
        key="application_control",
        label="Application control",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement=None,
        detail=(
            "Only a subset is reachable today, by matching an application's "
            "known hostnames over DNS and the TLS hostname. Distinguishing "
            "one application from another reliably needs deep packet "
            "inspection, which this platform does not have."
        ),
    ),
    SecurityFeature(
        key="threat_intelligence",
        label="Threat intelligence (malware, phishing, botnet)",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement=None,
        detail=(
            "Needs a maintained threat feed and a synchronisation pipeline. "
            "The delivery mechanism (DNS sinkhole, SNI rule, address-list) "
            "already exists; the intelligence behind it does not."
        ),
    ),
    SecurityFeature(
        key="geo_blocking",
        label="Geo blocking",
        availability=SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY,
        enforcement=None,
        detail=(
            "Needs a GeoIP database plus a periodic per-country CIDR sync. "
            "Inbound would be reliable; outbound would not, because CDN "
            "edges resolve into many countries."
        ),
    ),
    SecurityFeature(
        key="per_application_traffic",
        label="Per-application traffic accounting",
        availability=SecurityAvailability.NOT_SUPPORTED,
        enforcement=None,
        detail=(
            "Needs deep packet inspection or flow export plus a collector. "
            "This platform can attribute bytes per guest, device, zone and "
            "session, and cannot attribute them per application."
        ),
    ),
    SecurityFeature(
        key="ids_ips",
        label="Intrusion detection and prevention",
        availability=SecurityAvailability.NOT_SUPPORTED,
        enforcement=None,
        detail=(
            "RouterOS is not an intrusion-detection system. A UI for this "
            "would display signatures nothing evaluates."
        ),
    ),
    SecurityFeature(
        key="url_path_filtering",
        label="URL path and keyword filtering",
        availability=SecurityAvailability.NOT_SUPPORTED,
        enforcement=None,
        detail=(
            "Would need TLS interception, which breaks the certificate "
            "trust of every guest device on the network. Filtering is "
            "hostname-level by design."
        ),
    ),
)


def feature_by_key() -> dict[str, SecurityFeature]:
    return {feature.key: feature for feature in SECURITY_FEATURES}


__all__ = [
    "SECURITY_SCORE_MAX",
    "MIN_ROUTERS_FOR_SCORE",
    "SCORE_BAND_THRESHOLDS",
    "SCORE_FACTOR_WEIGHTS",
    "SECURITY_FEATURES",
    "SecurityAvailability",
    "SecurityFeature",
    "SecurityScoreBand",
    "ScoreFactorKey",
    "feature_by_key",
    "score_band_for",
]

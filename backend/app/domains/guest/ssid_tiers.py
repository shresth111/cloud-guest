"""Speed tiers by WiFi network (SSID) at Aruba Instant On venues -- the pure half.

## Why this exists

Instant On has no per-guest speed limit on any path we can reach (WISPr is
ignored on hardware, no role/VSA path, and its client policies cannot
rate-limit -- ~/wyfy-ops/aruba-ap21/INSTANT_ON_CLOUD_CONTROL.md). What it DOES
have is one per-client cap per SSID. So a venue that wants a free tier and a
paid tier runs two guest SSIDs (e.g. ``WYFY_FREE`` capped at 5 Mbps and
``WYFY_PREMIUM`` at 50 Mbps), and Wyfy decides who may join which.

## How

* ``location_ssid_tiers`` maps each SSID of a location to a tier: a display
  name, the per-guest speed Instant On should cap that SSID at, and whether
  joining it needs an entitlement (``requires_entitlement``).
* The AP sends ``Called-Station-Id = "<AP MAC>:<SSID>"`` (RFC 3580 s3.20;
  measured on the AP21 as ``54-F0-B1-C8-A9-0A:WYFY_ARUBA``).
  ``ssid_from_called_station_id`` takes the SSID out of it.
* RADIUS authorize on the shared Aruba listener admits a guest on an
  entitlement-only SSID only if ``entitles`` says so: a valid voucher pass
  (optionally of named voucher plans) or a mapping into the SSID's Access Tier.
  An open SSID admits every signed-in guest, so a premium guest may use both.

## Fail-open rules (deliberate)

* No SSID in the packet (bare MAC, empty, unparseable): no tier decision is
  possible, and refusing would lock every guest of the venue out on a firmware
  change, so the request is decided exactly as before this feature. Logged.
* An SSID with no mapping row: decided exactly as before (``WYFY_ARUBA`` and
  every venue that never configured tiers keep working unchanged).

Pure (no DB, no I/O) so the whole matrix is unit-testable.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

#: 802.11 SSIDs are at most 32 octets.
MAX_SSID_LENGTH = 32
#: Instant On's per-client cap is an integer number of Mbps, 1..1000.
MIN_TIER_MBPS = 1
MAX_TIER_MBPS = 1000

# The AP MAC at the front of Called-Station-Id, in any usual spelling, then a
# ':' and the SSID. The same MAC shapes ``aruba_shared._MAC_PREFIX_RE`` accepts.
_CALLED_STATION_RE = re.compile(
    r"^\s*(?:"
    r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}"  # aa:bb:.. / aa-bb-..
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"  # aabb.ccdd.eeff
    r"|[0-9A-Fa-f]{12}"  # aabbccddeeff
    r")(?![0-9A-Fa-f])"
    r"(?::(?P<ssid>.*))?$",
    re.DOTALL,
)


def ssid_from_called_station_id(raw: str | None) -> str | None:
    """The SSID after ``<AP MAC>:`` in ``Called-Station-Id``, or None.

    ``"54-F0-B1-C8-A9-0A:WYFY_FREE"`` -> ``"WYFY_FREE"``. An SSID may itself
    contain ``:`` (``"..:Cafe:Guest"`` -> ``"Cafe:Guest"``): only the first
    separator after the MAC splits. Surrounding whitespace and line endings are
    trimmed. None for a bare MAC, an empty SSID, a value that does not start
    with a MAC, or an SSID longer than 32 characters (not a real SSID)."""
    if not raw:
        return None
    match = _CALLED_STATION_RE.match(raw.strip())
    if match is None:
        return None
    ssid = (match.group("ssid") or "").strip()
    if not ssid or len(ssid) > MAX_SSID_LENGTH:
        return None
    return ssid


def ssid_key(ssid: str) -> str:
    """Comparison key. SSIDs are case-sensitive on the air, but two rows
    differing only in case at one venue would be an operator typo, so rows
    are unique case-insensitively and matched exactly first."""
    return ssid.strip().casefold()


@dataclass(frozen=True, slots=True)
class SsidTierRule:
    """One row of ``location_ssid_tiers``, as the decision sees it."""

    ssid: str
    tier_name: str
    requires_entitlement: bool
    policy_id: uuid.UUID | None = None
    voucher_plan_ids: tuple[uuid.UUID, ...] = ()
    download_mbps: int | None = None
    upload_mbps: int | None = None


@dataclass(frozen=True, slots=True)
class GuestEntitlement:
    """What the guest holds at this location.

    ``voucher_plan_ids`` -- the plan of every valid voucher pass the guest
    signed in with here (``None`` inside the set = a voucher with no plan).
    ``tier_policy_ids`` -- every Access Tier the guest is mapped into."""

    voucher_plan_ids: frozenset[uuid.UUID | None] = field(default_factory=frozenset)
    tier_policy_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)

    @property
    def has_voucher(self) -> bool:
        return bool(self.voucher_plan_ids)


NO_ENTITLEMENT = GuestEntitlement()


def entitles(rule: SsidTierRule, entitlement: GuestEntitlement) -> bool:
    """May a guest holding ``entitlement`` join ``rule``'s SSID?

    * open SSID: everyone signed in;
    * mapped into the SSID's Access Tier: yes;
    * a valid voucher pass: yes when the rule names no voucher plans, else
      only a voucher of one of those plans;
    * otherwise no."""
    if not rule.requires_entitlement:
        return True
    if rule.policy_id is not None and rule.policy_id in entitlement.tier_policy_ids:
        return True
    if entitlement.has_voucher:
        if not rule.voucher_plan_ids:
            return True
        return any(
            plan is not None and plan in rule.voucher_plan_ids
            for plan in entitlement.voucher_plan_ids
        )
    return False


class SsidDecisionReason:
    NO_SSID = "no_ssid"
    SSID_NOT_MAPPED = "ssid_not_mapped"
    OPEN_NETWORK = "open_network"
    ENTITLED = "entitled"
    NOT_ENTITLED = "not_entitled"


@dataclass(frozen=True, slots=True)
class SsidDecision:
    allowed: bool
    reason: str
    rule: SsidTierRule | None = None


def find_rule(rules: Iterable[SsidTierRule], ssid: str | None) -> SsidTierRule | None:
    if not ssid:
        return None
    rules = list(rules)
    for rule in rules:
        if rule.ssid == ssid:
            return rule
    key = ssid_key(ssid)
    for rule in rules:
        if ssid_key(rule.ssid) == key:
            return rule
    return None


def decide_ssid_access(
    rules: Sequence[SsidTierRule],
    ssid: str | None,
    entitlement: GuestEntitlement,
) -> SsidDecision:
    """The SSID half of the RADIUS decision. Only ``NOT_ENTITLED`` refuses."""
    if not ssid:
        return SsidDecision(True, SsidDecisionReason.NO_SSID)
    rule = find_rule(rules, ssid)
    if rule is None:
        return SsidDecision(True, SsidDecisionReason.SSID_NOT_MAPPED)
    if not rule.requires_entitlement:
        return SsidDecision(True, SsidDecisionReason.OPEN_NETWORK, rule)
    if entitles(rule, entitlement):
        return SsidDecision(True, SsidDecisionReason.ENTITLED, rule)
    return SsidDecision(False, SsidDecisionReason.NOT_ENTITLED, rule)


def upgrade_networks(
    rules: Sequence[SsidTierRule],
    entitlement: GuestEntitlement,
    *,
    current_ssid: str | None,
) -> list[SsidTierRule]:
    """Entitlement-only SSIDs this guest may join, other than the one they are
    on: the "join WYFY_PREMIUM" hint after a purchase/voucher."""
    current = ssid_key(current_ssid) if current_ssid else None
    return [
        rule
        for rule in rules
        if rule.requires_entitlement
        and ssid_key(rule.ssid) != current
        and entitles(rule, entitlement)
    ]


__all__ = [
    "MAX_SSID_LENGTH",
    "MAX_TIER_MBPS",
    "MIN_TIER_MBPS",
    "NO_ENTITLEMENT",
    "GuestEntitlement",
    "SsidDecision",
    "SsidDecisionReason",
    "SsidTierRule",
    "decide_ssid_access",
    "entitles",
    "find_rule",
    "ssid_from_called_station_id",
    "ssid_key",
    "upgrade_networks",
]

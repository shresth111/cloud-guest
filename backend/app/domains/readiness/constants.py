"""Enumerations and the fixed checklist-item registry for the Router
Readiness Checklist domain.

``CHECKLIST_ITEMS`` is the single source of truth for which 16 items exist,
their display copy, and whether each is auto-detectable today. Adding a new
item is additive (append here; no migration needed -- ``item_key`` is a
plain string column, the same "no native enum type" posture
``app.domains.otp.constants``/``app.domains.voucher.constants`` already
document).

**Auto-detected today** (``DetectionMode.AUTO``, zero new device I/O --
computed live in ``service.py``'s ``run_auto_detection`` from telemetry this
platform already collects): ``HEARTBEAT``, ``SAAS_PROVISIONING``,
``WAN_CONNECTIVITY``, ``WIREGUARD``, ``API_REACHABILITY``,
``GUEST_DATA_PATH``, and ``ROGUE_DHCP_GUARD``.

``ROGUE_DHCP_GUARD`` is the one AUTO item whose evidence originates on a
device rather than in telemetry this platform already holds -- and it still
costs this domain zero new device I/O, because it reads only the row
``app.domains.dhcp.tasks``'s scheduled detector persisted hours earlier.
That split (detector writes, surface reads) is what lets a real device fact
appear on a checklist whose read path re-runs on every GET.

**Manual-only for now** (``DetectionMode.MANUAL`` -- an operator ticks these
after checking on-site or via another tab; ``service.py``'s
``confirm_item`` is the only way their status ever changes): the remaining
nine. Several of these (LAN DHCP, Hotspot, Captive portal, DNS, Firewall
rule presence, reboot-persistence) could become auto-detected with one small
new read-only adapter call each, matching the pattern
``app.domains.connected_devices`` already uses -- deliberately left manual
in this pass rather than adding five new adapter calls to ship the
checklist itself. Two (RADIUS live-auth testing, DoH/DoT blocking) have no
supporting capability anywhere in the codebase yet -- RADIUS synthetic-auth
has no test harness, and DoH/DoT blocking has no config-generation support
in ``app.domains.network_config.renderers`` to check *against* -- so these
stay manual until that capability exists independently of this domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ChecklistItemStatus(StrEnum):
    """The current state of one checklist item for one router."""

    NOT_CHECKED = "not_checked"
    PASS = "pass"
    FAIL = "fail"
    MANUALLY_CONFIRMED = "manually_confirmed"
    MANUALLY_FAILED = "manually_failed"


# Statuses that read as "this item is in good shape" for the checklist's
# own summary counts (``schemas.ChecklistSummary``).
PASSING_STATUSES: frozenset[ChecklistItemStatus] = frozenset(
    {ChecklistItemStatus.PASS, ChecklistItemStatus.MANUALLY_CONFIRMED}
)
FAILING_STATUSES: frozenset[ChecklistItemStatus] = frozenset(
    {ChecklistItemStatus.FAIL, ChecklistItemStatus.MANUALLY_FAILED}
)


class DetectionMode(StrEnum):
    """How a given row's ``status`` was last set -- not a fixed property of
    the item itself. An item whose *definition* is ``AUTO`` still gets a
    row with ``detection_mode=MANUAL`` the moment an operator overrides it
    (e.g. confirming WireGuard by hand because this router genuinely has no
    tunnel and the auto-check honestly can't tell "not configured" from
    "broken") -- the next auto re-check overwrites it back to ``AUTO``."""

    AUTO = "auto"
    MANUAL = "manual"


class ChecklistItemKey(StrEnum):
    HEARTBEAT = "heartbeat"
    SAAS_PROVISIONING = "saas_provisioning"
    WAN_CONNECTIVITY = "wan_connectivity"
    GUEST_DATA_PATH = "guest_data_path"
    WIREGUARD = "wireguard"
    API_REACHABILITY = "api_reachability"
    GUEST_SIGN_IN = "guest_sign_in"
    LAN_DHCP = "lan_dhcp"
    CAPTIVE_PORTAL = "captive_portal"
    DNS = "dns"
    FIREWALL = "firewall"
    RADIUS_AUTH = "radius_auth"
    RADIUS_ACCOUNTING = "radius_accounting"
    ROGUE_DHCP_GUARD = "rogue_dhcp_guard"
    DOH_DOT_BLOCKING = "doh_dot_blocking"
    REBOOT_PERSISTENCE = "reboot_persistence"


class ChecklistCategory(StrEnum):
    """Groups items for display only -- never branched on in ``service.py``."""

    CONNECTIVITY = "connectivity"
    GUEST_EXPERIENCE = "guest_experience"
    SECURITY = "security"
    RESILIENCE = "resilience"


@dataclass(frozen=True)
class ChecklistItemDefinition:
    key: ChecklistItemKey
    label: str
    description: str
    detection_mode: DetectionMode
    category: ChecklistCategory


CHECKLIST_ITEMS: tuple[ChecklistItemDefinition, ...] = (
    ChecklistItemDefinition(
        key=ChecklistItemKey.HEARTBEAT,
        label="Agent heartbeat",
        description="The router agent is checking in on schedule.",
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.CONNECTIVITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.SAAS_PROVISIONING,
        label="SaaS provisioning",
        description="This router has an active platform credential and is online.",
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.CONNECTIVITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.WAN_CONNECTIVITY,
        label="WAN connectivity",
        description="At least one enabled WAN link is passing its health check.",
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.CONNECTIVITY,
    ),
    # THE ITEM THAT WOULD HAVE CAUGHT 2026-08-27.
    #
    # Every other item here asks whether something the platform configured
    # is currently working. This one asks whether the platform ever
    # configured it at all -- a different and, as it turns out, more
    # dangerous question. Venue "huda city center" passed heartbeat, SaaS
    # provisioning, WireGuard and API reachability, and every guest who
    # authenticated had no internet, because no NAT rule had ever been
    # asserted for that router and nothing anywhere said so.
    #
    # Deliberately NOT folded into WAN_CONNECTIVITY above. That item
    # returns NOT_CHECKED when a router has no enabled ISP link -- which is
    # correct for a question about *link health* (there is no link to
    # assess) and is exactly why it could not surface this: NOT_CHECKED is
    # not in FAILING_STATUSES, so a router with no data path at all counted
    # as nothing-wrong. Two different claims deserve two rows.
    ChecklistItemDefinition(
        key=ChecklistItemKey.GUEST_DATA_PATH,
        label="Guest data path",
        description=(
            "The platform has asserted a route to the internet for this "
            "router's guests -- an enabled WAN link, or an applied config "
            "version. Without one, guests authenticate successfully and "
            "then have nowhere to send a packet."
        ),
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.CONNECTIVITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.WIREGUARD,
        label="WireGuard tunnel",
        description=(
            "The management tunnel has a recent handshake, if one is configured."
        ),
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.CONNECTIVITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.API_REACHABILITY,
        label="API reachability",
        description=(
            "The platform's most recent reachability check against this "
            "router's own API succeeded."
        ),
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.CONNECTIVITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.GUEST_SIGN_IN,
        label="Guest sign-in",
        description=(
            "A test device can join the guest network and complete sign-in end to end."
        ),
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.GUEST_EXPERIENCE,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.LAN_DHCP,
        label="LAN DHCP",
        description="The LAN DHCP pool is handing out addresses as configured.",
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.GUEST_EXPERIENCE,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.CAPTIVE_PORTAL,
        label="Captive portal",
        description=(
            "The captive portal page loads and redirects correctly on a fresh device."
        ),
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.GUEST_EXPERIENCE,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.DNS,
        label="DNS resolution",
        description="Guest devices can resolve external hostnames.",
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.GUEST_EXPERIENCE,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.FIREWALL,
        label="Firewall rules present",
        description=(
            "The expected guest-isolation firewall rules are in place on the device."
        ),
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.SECURITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.RADIUS_AUTH,
        label="RADIUS authentication",
        description="A test RADIUS authentication against this router succeeds.",
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.SECURITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.RADIUS_ACCOUNTING,
        label="RADIUS accounting",
        description="RADIUS accounting records are being received for this router.",
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.SECURITY,
    ),
    # Reads a persisted row and nothing else. The device read that produced
    # it happened hours earlier, off the request path, in
    # ``app.domains.dhcp.tasks`` -- which is what lets an AUTO item exist
    # here at all without breaking this domain's zero-new-device-I/O rule
    # (``service.get_checklist`` re-runs every AUTO item on every GET, so
    # anything it calls is on a hot path).
    #
    # DETECTION ONLY, and the copy must stay that way. RouterOS's
    # ``/ip dhcp-server alert`` writes a log entry when it sees a DHCP
    # server it does not trust. It does not drop the offer, block the port,
    # or rate-limit anything. "Protected"/"blocked"/"guarded" would each
    # describe a capability the feature does not have, and an operator who
    # believed it would stop looking for the rogue server -- which is the
    # actual harm. The item KEY says guard for continuity with
    # ``app.domains.dhcp.constants.RogueDhcpAlertState``'s own vocabulary
    # and the gateway contract's ``guarded`` property; the label and
    # description, the only parts a human reads, say detection.
    ChecklistItemDefinition(
        key=ChecklistItemKey.ROGUE_DHCP_GUARD,
        label="Rogue DHCP detection",
        description=(
            "This router is watching for another DHCP server on the guest "
            "network. Detection only -- it logs, it does not block."
        ),
        detection_mode=DetectionMode.AUTO,
        category=ChecklistCategory.SECURITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.DOH_DOT_BLOCKING,
        label="DoH/DoT blocking",
        description=(
            "DNS-over-HTTPS/TLS bypass is blocked, keeping content filtering "
            "effective."
        ),
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.SECURITY,
    ),
    ChecklistItemDefinition(
        key=ChecklistItemKey.REBOOT_PERSISTENCE,
        label="Reboot persistence",
        description=(
            "Configuration survives a reboot -- confirmed after a real power cycle."
        ),
        detection_mode=DetectionMode.MANUAL,
        category=ChecklistCategory.RESILIENCE,
    ),
)

CHECKLIST_ITEMS_BY_KEY: dict[ChecklistItemKey, ChecklistItemDefinition] = {
    item.key: item for item in CHECKLIST_ITEMS
}

__all__ = [
    "ChecklistItemStatus",
    "PASSING_STATUSES",
    "FAILING_STATUSES",
    "DetectionMode",
    "ChecklistItemKey",
    "ChecklistCategory",
    "ChecklistItemDefinition",
    "CHECKLIST_ITEMS",
    "CHECKLIST_ITEMS_BY_KEY",
]

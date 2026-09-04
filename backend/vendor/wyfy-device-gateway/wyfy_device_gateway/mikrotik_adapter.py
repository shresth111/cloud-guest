"""``MikroTikAdapter`` -- a real, fully-functional ``DeviceGatewayAdapter``
implementation, ported (not reinvented) from the six existing
``librouteros``-based adapters audited in PRD section 2.1:

1. ``cloud-guest-repo/backend/app/domains/router/device_adapters.py``
2. ``cloud-guest-repo/backend/app/domains/isp/device_adapters.py``
3. ``cloud-guest-repo/backend/app/domains/connected_devices/device_adapters.py``
4. ``cloud-guest-repo/backend/app/domains/provisioning_engine/device_adapters.py``
5. ``cloud-guest-repo/backend/app/domains/queue_management/device_adapters.py``
6. ``cloud-guest-repo/backend/app/domains/network_diagnostics/device_adapters.py``

plus the real RouterOS command shapes documented in
``cloud-guest-repo/backend/app/domains/network_config/renderers.py`` (the
config-*push* renderer for VLAN/DHCP/port-forward/RADIUS-client config,
today emitted as script text for an external agent -- here, the same
commands are issued directly over the structured ``librouteros`` API,
mirroring ``queue_management.device_adapters.MikroTikQueueAdapter``'s own
``Path.add``/``.update`` precedent for turning a rendered-config concept
into real API writes).

## Honest scope: real client code, never exercised end-to-end here

Same posture as every adapter it's ported from: there is no live MikroTik
device anywhere in this sandbox. Every method below, if actually invoked,
will raise a real connection error the moment it tries to open a real
socket -- never a fabricated result. This module's own command-
construction and response-parsing logic is exercised in
``tests/test_mikrotik_adapter.py`` via a fake/mocked transport (mocking
``librouteros.connect`` and the object it returns), never against a real
device.

## Two ports, not one -- why ``creds.extra["ssh_port"]`` exists

Every read/write operation below except ``provision_device`` uses
MikroTik's structured RouterOS API (``librouteros``, default TCP port
8728, taken from ``creds.port``). ``provision_device`` is the one
operation ported from ``provisioning_engine.device_adapters`` that
genuinely needs SSH + SFTP instead (RouterOS's API protocol has no
file-transfer primitive; ``/import`` is a file-system-level operation --
see that module's own docstring for the full "why both librouteros AND
asyncssh" reasoning, mirrored here unchanged). Since
``DeviceCredentials`` (the vendor-agnostic contract type) has only one
``port`` field, the SSH port is read from ``creds.extra["ssh_port"]``
(defaulting to 22 if absent/unparsable) -- exactly the escape hatch the
contract's own docstring describes ``extra`` as being for.

## RADIUS client config: ``src-address`` (WireGuard tunnel IP) intentionally omitted

The real ``render_radius_client`` in cloud-guest-repo also sets
``src-address=<wireguard tunnel ip>`` on the ``/radius add`` line -- that
value is specific to cloud-guest-repo's own WireGuard-tunnel network
topology (per this project's own policy, WireGuard/tunnel internals are
Master-console/backend-only, never a concept this vendor-agnostic package
should need to know about). ``RadiusClientConfig`` (the contract type)
correctly has no tunnel-IP field, so this port only emits the vendor-
generic RADIUS fields (host/secret/ports) real RouterOS accepts; the
``src-address`` refinement remains cloud-guest-repo's own concern to layer
on top if/when it migrates this call site (e.g. via ``creds.extra``).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import uuid
from collections.abc import Mapping, Sequence

import asyncssh
import librouteros
from librouteros.exceptions import LibRouterosError

from .contract import (
    ConnectedDevice,
    ContentFilterRuleConfig,
    DefaultRoute,
    DeviceCredentials,
    DeviceDiscoveryResult,
    DeviceHealthResult,
    DeviceVendor,
    DhcpPoolConfig,
    HotspotActiveSession,
    HotspotDisconnectResult,
    HotspotSessionControl,
    InterfaceInfo,
    IpAddressInfo,
    NatRuleConfig,
    NetworkSnapshot,
    PingResult,
    PortForwardConfig,
    ProvisionResult,
    QosPacketMarkConfig,
    QueueDeviceStatus,
    RadiusClientConfig,
    RawCommandResult,
    RogueDhcpAlertConfig,
    RogueDhcpAlertStatus,
    SpeedTestResult,
    TracerouteHop,
    TracerouteResult,
    VlanConfig,
    VlanHotspotConfig,
    WanHealth,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_SSH_PORT = 22
# ported from provisioning_engine/device_adapters.py's own module-level
# filename constants -- push_config/verify_config and backup/restore each
# round-trip through the *same* filename, so they must stay in sync with
# each other exactly like the original did.
_PROVISIONING_ENGINE_CONFIG_FILENAME = "cloudguest-config.rsc"
_PROVISIONING_ENGINE_BACKUP_FILENAME = "cloudguest-backup.backup"

# Content filtering: same real, honest DNS-sinkhole + address-list scope
# as ``cloud-guest-repo/backend/app/domains/network_config/renderers.py``
# ``render_content_filter_rule``/``render_content_filter_enforcement`` --
# see ``configure_content_filter_rule``'s own docstring below. These two
# literal values are independently duplicated (not imported -- this
# vendor package cannot depend on ``app.domains``, see module docstring)
# from ``app.domains.content_filtering.constants``; keeping the literal
# *values* identical across both copies is what keeps them describing the
# same real device-side objects.
_CONTENT_FILTER_SINKHOLE_ADDRESS = "127.0.0.1"
# Stamped on the ``/radius`` NAS row this platform manages. Not used as
# the lookup key -- see ``set_radius_client_config`` for why the natural
# key (service + server address) is, and why an existing hand-written row
# is adopted rather than duplicated.
_RADIUS_CLIENT_COMMENT = "WyfyGuest RADIUS NAS client"
_CONTENT_FILTER_ADDRESS_LIST_NAME = "wyfyguest-content-filter-blocked"
# Rogue DHCP detection: the marker stamped on every ``/ip dhcp-server
# alert`` row this platform manages.
#
# Deliberately the SAME literal the hand-run probe
# (``cloud-guest-repo/backend/ops/probes/setup_dhcp_alert.py``) already
# wrote onto the lab router. RouterOS holds one alert per interface, so a
# different marker here would not add a second row -- it would make the
# writer fail to recognize its own predecessor's work and leave the
# operator's carefully-checked rows unmanaged. The marker is not the lookup
# key (the interface is -- see ``configure_rogue_dhcp_alerts``); it is what
# tells an operator reading ``/ip dhcp-server alert`` on the device, and
# the reader's ``managed`` flag, where a row came from.
_ROGUE_DHCP_ALERT_COMMENT = "cloudguest-rogue-dhcp-watch"
_CONTENT_FILTER_ENFORCEMENT_COMMENT = (
    "Wyfy Guest content filtering: block listed addresses"
)
# The marker that makes one content-filtering rule's own objects findable
# again on the next push, exactly as ``_NAT_RULE_COMMENT_PREFIX`` does for a
# VLAN's masquerade rule. It is deliberately built from the rule's id rather
# than from anything RouterOS matches on: ``name``/``regexp``/``address``
# are the blocked target -- the one field a customer edits -- and ``label``
# is the name they gave it, so keying on either leaves the previous objects
# behind still blocking a site the customer already unblocked. See
# ``configure_content_filter_rule``'s own docstring.
_CONTENT_FILTER_RULE_COMMENT_PREFIX = "WyfyGuest content filter "
# Appended to the marker of the second, subdomain-matching DNS entry, so the
# two entries one domain rule creates stay individually addressable.
_CONTENT_FILTER_SUBDOMAIN_MARKER_SUFFIX = " (subdomains)"
# NAT / internet access: the marker that makes one VLAN's masquerade rule
# findable again on the next push. It is deliberately the rule's *identity*
# rather than any of its RouterOS fields -- ``src-address`` is exactly what
# an operator edits, so keying on it would leave the old rule behind and add
# a second one. See ``configure_nat_masquerade``'s own docstring.
_NAT_RULE_COMMENT_PREFIX = "WyfyGuest VLAN "
# QoS: the same marker trick again, for the ``/ip firewall mangle`` rule
# that sets one QoS rule's packet mark. Every RouterOS field on that rule --
# ``protocol``, ``dst-port``, ``dscp``, even ``new-packet-mark`` itself,
# which is derived from the customer's own rule name -- is something an
# edit changes, so the row id is the only stable handle. See
# ``configure_qos_packet_mark``'s own docstring.
_QOS_MANGLE_COMMENT_PREFIX = "WyfyGuest qos "
# The mangle fields that carry a QoS rule's *match*. Listed so a rule
# re-typed between a port-range match and a DSCP one can be detected: the
# fields the old match used are still on the device row and are not in the
# new desired set, and RouterOS's update has no way to unset them.
_QOS_MANGLE_MATCH_FIELDS = ("protocol", "dst-port", "dscp")
# WAN failover: the markers on the two objects ``ensure_wan_egress`` may add
# so that traffic leaving a newly-preferred uplink is masqueraded and treated
# as WAN-facing.
#
# INTERFACE-DERIVED, AND ONE PER INTERFACE ON PURPOSE. The alternative --
# a single "the failover masquerade" rule whose ``out-interface`` is
# rewritten on every failover -- is a *mutation of a live router-wide NAT
# rule*, which is the class of change that took a guest network down on
# 2026-08-18. Keyed per interface, every push this makes is an ADD of an
# object that did not exist, and an add cannot break what already works: a
# masquerade rule matches only traffic that actually leaves its own
# ``out-interface``, so the rule for a backup uplink is inert for as long as
# nothing is routed that way.
_UPLINK_NAT_COMMENT_PREFIX = "cloudguest-nat-uplink-"
_UPLINK_WAN_LIST_COMMENT_PREFIX = "cloudguest-wanlist-uplink-"
# Fields that narrow a masquerade rule to less than "everything leaving this
# interface". A rule carrying any of them may be someone else's deliberately
# scoped NAT (one VLAN's own ``WyfyGuest VLAN <id>`` rule is exactly this
# shape, with ``src-address`` set) and is therefore NOT evidence that guest
# traffic in general is masqueraded out of that interface.
_NAT_NARROWING_FIELDS = (
    "src-address",
    "src-address-list",
    "dst-address",
    "dst-address-list",
    "in-interface",
    "in-interface-list",
    "protocol",
    "src-port",
    "dst-port",
    "port",
)


def _uplink_nat_comment(interface: str) -> str:
    return f"{_UPLINK_NAT_COMMENT_PREFIX}{interface}"


def _uplink_wan_list_comment(interface: str) -> str:
    return f"{_UPLINK_WAN_LIST_COMMENT_PREFIX}{interface}"


def _nat_rule_comment(vlan_id: int) -> str:
    return f"{_NAT_RULE_COMMENT_PREFIX}{vlan_id}"


# Port forwarding: the same marker trick, for the same reason. The handle
# is the caller's own row id, because every RouterOS field on a DSTNAT rule
# -- dst-port, to-addresses, to-ports, protocol -- is one a customer edits.
# ``<prefix><rule_id> <protocol>``: one device rule per transport, because a
# "both" rule cannot be expressed as one (see ``configure_port_forward``),
# and the trailing token keeps the two apart without giving up the row's
# single identity.
_PORT_FORWARD_COMMENT_PREFIX = "WyfyGuest PF "
# The transports a "both" rule really means on a device.
_PORT_FORWARD_BOTH_PROTOCOLS = ("tcp", "udp")


def _port_forward_comment(rule_id: str, protocol: str) -> str:
    return f"{_PORT_FORWARD_COMMENT_PREFIX}{rule_id} {protocol}"


def _port_forward_protocols(protocol: str) -> tuple[str, ...]:
    """Which transports one stored rule occupies on the device.

    ``both`` is a value this platform's own port-forwarding domain stores
    and defaults to, not a RouterOS one: ``dst-port`` is only accepted
    alongside a tcp or udp ``protocol``, so a single rule cannot say it.
    ``render_port_forwarding_rule`` handles the same case by omitting
    ``protocol=`` entirely, which a real router rejects.
    """
    if protocol.strip().lower() == "both":
        return _PORT_FORWARD_BOTH_PROTOCOLS
    return (protocol,)


def _owns_port_forward_comment(comment: object, rule_id: str) -> bool:
    """Whether a ``/ip firewall nat`` row belongs to this stored rule.

    Prefix-matched on the id and then on a separator, never on the bare
    prefix: matching ``"WyfyGuest PF <id>"`` alone would also claim a row
    belonging to a rule whose id merely starts with these characters.
    """
    if not isinstance(comment, str):
        return False
    owner = f"{_PORT_FORWARD_COMMENT_PREFIX}{rule_id}"
    return comment == owner or comment.startswith(f"{owner} ")
def _qos_marker(rule_id: str) -> str:
    """The identity half of a QoS mangle rule's comment.

    Ends in ``": "`` for the reason :func:`_content_filter_marker` does:
    the customer's own label follows in the same field, and the marker of
    one rule must never be a prefix of another's.
    """
    return f"{_QOS_MANGLE_COMMENT_PREFIX}{rule_id}: "


def _qos_comment(rule_id: str, label: str, priority: int) -> str:
    """The whole comment: identity first, then what an operator reading
    ``/ip firewall mangle`` on the router needs to recognize the rule --
    the customer's name for it and the priority the paired queue applies.

    The priority is *not* configuration here; the ``/queue tree`` entry is
    what actually sets it. It rides along in the comment because a mangle
    rule read in isolation otherwise says nothing about what the mark is
    worth, and ``network_config.renderers.render_qos_traffic_rule``'s own
    rendered comment already carried it.
    """
    return f"{_qos_marker(rule_id)}{label} (priority={priority})"


def _qos_mangle_fields(rule: QosPacketMarkConfig) -> dict[str, str]:
    """The desired ``/ip firewall mangle`` row for one QoS rule.

    Deliberately the same command shape
    ``network_config.renderers.render_qos_traffic_rule`` already emits --
    ``chain=prerouting``, the port-range or DSCP match, ``mark-packet``,
    ``passthrough=no`` -- so a router that has had a config script pushed
    and a router pushed directly through this method end up carrying the
    same rule, not two competing ideas of one.
    """
    fields: dict[str, str] = {"chain": "prerouting"}
    if rule.port_range_start is not None and rule.port_range_end is not None:
        if rule.protocol:
            fields["protocol"] = rule.protocol
        fields["dst-port"] = f"{rule.port_range_start}-{rule.port_range_end}"
    else:
        fields["dscp"] = str(rule.dscp_value)
    fields["action"] = "mark-packet"
    fields["new-packet-mark"] = rule.packet_mark
    fields["passthrough"] = "no"
    fields["comment"] = _qos_comment(rule.rule_id, rule.label, rule.priority)
    return fields


def _content_filter_marker(rule_id: str, *, subdomains: bool = False) -> str:
    """The identity half of a content-filtering object's comment.

    Ends in ``": "`` so the customer's own label can follow it in the same
    field without the marker ever being a prefix of another rule's -- and
    so the non-subdomain marker is not a prefix of the subdomain one, which
    branches at ``" ("`` before the colon is reached.
    """
    suffix = _CONTENT_FILTER_SUBDOMAIN_MARKER_SUFFIX if subdomains else ""
    return f"{_CONTENT_FILTER_RULE_COMMENT_PREFIX}{rule_id}{suffix}: "


def _content_filter_comment(
    rule_id: str, label: str, *, subdomains: bool = False
) -> str:
    """The whole comment: identity first, then the customer's label.

    The label is carried onto the device rather than dropped because it is
    the only thing that tells an operator reading ``/ip dns static`` on the
    router what a sinkholed name is for. It is mutable, and treated as
    such: a renamed rule updates this field in place, found by the marker
    the rename cannot touch.
    """
    return f"{_content_filter_marker(rule_id, subdomains=subdomains)}{label}"


class _HotspotNames:
    """The six RouterOS object names one VLAN's captive portal occupies.

    Derived from ``vlan_id`` alone, exactly as
    ``network_config.renderers._render_vlan_hotspot`` derives them, so a
    portal this adapter pushes and the same portal rendered into a config
    script are the same objects rather than two competing sets. ``vlan_id``
    is the real, per-router-unique identity; the VLAN's display name is
    not unique and never appears in an object name.
    """

    __slots__ = ("tag", "pool", "dhcp_server", "profile", "server")

    def __init__(self, vlan_id: int) -> None:
        self.tag = f"vlan{vlan_id}"
        self.pool = f"{self.tag}-hs-pool"
        self.dhcp_server = f"{self.tag}-hs-dhcp"
        self.profile = f"{self.tag}-hsprof"
        self.server = f"{self.tag}-hotspot"

    @property
    def dns_comment(self) -> str:
        return f"{self.tag}-hotspot-dns-name"

    @property
    def network_owner(self) -> str:
        """Marker stamped on this portal's ``/ip dhcp-server network`` row.

        A DHCP pool on the same subnet writes a row keyed identically --
        RouterOS identifies that row by subnet alone -- so without a marker
        one feature's teardown silently removes the other's.
        """
        return f"WyfyGuest portal {self.tag}"


def _hotspot_pool_range(cidr: str, gateway: str) -> str | None:
    """The address range a VLAN's captive portal hands out: the largest
    run of hosts in ``cidr`` that does not contain ``gateway``.

    ``_render_vlan_hotspot`` computes this as "every host except the
    gateway", then emits ``first-last`` -- which is the same answer
    whenever the gateway sits at either end of the subnet (``.1`` in a
    ``/24``, the shape every VLAN this platform creates actually has), and
    a real defect when it does not: with a gateway at ``.100`` the emitted
    ``.1-.254`` spans it, and the DHCP server can lease the router's own
    address to a guest. Taking the largest gateway-free run instead is
    identical in the common case and correct in the uncommon one.

    ``None`` when the subnet has no host left to hand out -- a ``/32``,
    a ``/31``, or a gateway that is the only host. The caller refuses
    rather than pushing a pool with an empty range.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    gateway_ip = ipaddress.ip_address(gateway)
    runs: list[list[object]] = []
    current: list[object] = []
    for host in network.hosts():
        if host == gateway_ip:
            if current:
                runs.append(current)
                current = []
            continue
        current.append(host)
    if current:
        runs.append(current)
    if not runs:
        return None
    widest = max(runs, key=len)
    return f"{widest[0]}-{widest[-1]}"


_MAC_ADDRESS_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2})[:\-]([0-9A-Fa-f]{2})[:\-]([0-9A-Fa-f]{2})"
    r"[:\-]([0-9A-Fa-f]{2})[:\-]([0-9A-Fa-f]{2})[:\-]([0-9A-Fa-f]{2})$"
)

# RouterOS duration tokens: an integer immediately followed by one of these
# unit suffixes, e.g. "1ms200us", "850us", "2s", "1m30s" -- ported verbatim
# from isp/device_adapters.py and network_diagnostics/device_adapters.py
# (both carried an identical copy of this parser).
_ROUTEROS_DURATION_TOKEN = re.compile(r"(\d+)(d|h|ms|us|s|m)")
_ROUTEROS_DURATION_UNIT_TO_MS: dict[str, float] = {
    "d": 86_400_000.0,
    "h": 3_600_000.0,
    "m": 60_000.0,
    "s": 1_000.0,
    "ms": 1.0,
    "us": 0.001,
}


class MikroTikDeviceError(Exception):
    """Raised for both connection and operation failures against a real
    MikroTik device -- consolidates the several per-domain exception
    hierarchies (``DeviceInterfaceQueryError``, ``IspDeviceConnectionError``,
    ``ProvisionDeviceOperationError``, etc.) the six source files each
    defined independently for the exact same underlying failure modes."""

    def __init__(self, host: str, detail: str) -> None:
        self.host = host
        self.detail = detail
        super().__init__(f"MikroTik device error ({host}): {detail}")


class MikroTikConnectionError(MikroTikDeviceError):
    """Raised specifically when *opening* a connection (RouterOS API or
    SSH) to a real MikroTik device fails -- as opposed to a command/
    operation failing after a connection was already successfully
    established (plain :class:`MikroTikDeviceError`, the base class,
    still covers both cases for ``except MikroTikDeviceError`` callers
    that don't need the distinction, e.g. ``router/device_adapters.py``'s
    single-exception-type domain).

    Several of the source domains this package ports from (``isp``,
    ``network_diagnostics``, ``connected_devices``, ``queue_management``,
    ``provisioning_engine``) each define their own real, distinct
    ``XDeviceConnectionError``/``XDeviceOperationError`` pair -- and at
    least one of them (``provisioning_engine.device_adapters
    .MikroTikProvisionAdapter.health_check``) genuinely branches on which
    one occurred (a connection failure is reported as a graceful
    ``healthy=False`` result; a post-connection *operation* failure is not
    caught there at all and propagates as a real exception). Callers that
    need to preserve that distinction should catch this subclass first,
    then the base class."""


class MikroTikWanInterfaceError(MikroTikDeviceError):
    """Raised when the router's own WAN-facing interface cannot honestly
    be determined from its live state -- see
    :meth:`MikroTikAdapter.resolve_wan_interface`.

    A distinct type because the caller genuinely wants to distinguish it:
    every other failure here means "the device rejected an operation", but
    this one means "the device is not currently telling us where the
    internet is", which is a real, operator-fixable condition (no usable
    default route, or a default route whose gateway sits on no known
    interface) and reads as nonsense when reported as a NAT push failure.

    Deliberately raised instead of falling back to a guess. Masquerading
    out of the wrong interface does not fail loudly -- it silently NATs
    guest traffic onto an internal segment, or matches nothing at all and
    leaves a VLAN with no internet while the push reports success."""


class MikroTikRouteNotFoundError(MikroTikDeviceError):
    """A caller named an interface that has no ``0.0.0.0/0`` route in the
    device's own ``main`` table.

    Distinct from :class:`MikroTikWanInterfaceError`, which is "the device
    will not say where the internet is at all". This one is narrower and
    more alarming: the platform believes an uplink terminates on this
    interface and the router has no default route there, so the two
    disagree about the site's topology. Failing over onto it would produce
    a dashboard that names an uplink no traffic can use."""


class MikroTikAmbiguousRouteError(MikroTikDeviceError):
    """More than one default route resolves to the same interface, or more
    than one shares the lowest distance on the device.

    Both are states where "which route is the preferred one" has no single
    answer, and both are states a distance change would make worse rather
    than better -- two routes tied at the lowest distance is RouterOS load
    sharing, and lowering a third to join them adds a third share.
    Refused rather than resolved by picking the first row, because row
    order in a RouterOS reply is not a decision anyone made."""


class MikroTikImmutableRouteError(MikroTikDeviceError):
    """The route that would have to be modified is ``dynamic`` -- RouterOS
    created it itself (a dhcp-client's own auto-route) and refuses
    ``/ip route set`` on it.

    Checked before the write rather than discovered from the device's
    refusal, so the error names the interface and says what an operator can
    do about it (this platform's own Setup Script generator provisions a
    *static* default route per WAN precisely so this case does not arise --
    a router showing this one was not provisioned by it, or has had its
    routes replaced since)."""


def normalize_mac_address(value: object) -> str | None:
    """Ported verbatim from
    ``connected_devices/validators.py::normalize_mac_address`` -- canonical
    uppercase colon-separated form, or ``None`` if not a real six-octet MAC
    at all. Lenient by design, never raises."""
    if not value:
        return None
    match = _MAC_ADDRESS_PATTERN.match(str(value).strip())
    if match is None:
        return None
    return ":".join(octet.upper() for octet in match.groups())


def _parse_routeros_duration_ms(value: object) -> float | None:
    """Ported verbatim from ``isp/device_adapters.py`` /
    ``network_diagnostics/device_adapters.py`` (both carried an identical
    copy). Parses a RouterOS duration string (e.g. ``"1ms200us"``,
    ``"850us"``, ``"12ms"``, ``"2s"``) into a plain float of milliseconds.
    Returns ``None`` for anything empty/unparsable rather than raising."""
    if not value:
        return None
    text = str(value)
    total_ms = 0.0
    matched_any = False
    for amount, unit in _ROUTEROS_DURATION_TOKEN.findall(text):
        total_ms += int(amount) * _ROUTEROS_DURATION_UNIT_TO_MS[unit]
        matched_any = True
    return total_ms if matched_any else None


def _safe_int(value: object, *, default: int | None = None) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value: object, *, default: float | None = None) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _safe_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _describe_exception(exc: BaseException) -> str:
    """Returns a human-readable, never-empty description of a caught
    low-level exception for use as a ``MikroTikConnectionError``/
    ``MikroTikDeviceError`` ``detail``.

    ``str(exc)`` is empty for a real, common failure mode here: the
    connect-timeout every ``_ssh_connect``/``_connect_api`` caller waits on
    via ``asyncio.wait_for(..., timeout=...)`` raises a bare
    ``TimeoutError()`` with no message when it expires (``str(TimeoutError())
    == ""``) -- and ``TimeoutError`` is a subclass of ``OSError``, so it is
    caught by every ``except (OSError, asyncssh.Error)``/
    ``except (LibRouterosError, OSError)`` clause in this module right
    alongside genuine connection-refused/DNS-failure errors that do carry a
    message. Without this fallback, an operator sees a connection error
    that ends in an empty string after its own colon (e.g. "Could not
    connect to device at '10.20.0.45': ") with zero indication of what
    actually happened -- confirmed live in production for a router whose
    WireGuard tunnel had never handshaked: the SSH connect attempt over the
    tunnel IP simply timed out, and that timeout's own exception carried no
    text to surface.
    """
    text = str(exc).strip()
    if text:
        return text
    if isinstance(exc, TimeoutError):
        return "connection attempt timed out"
    return type(exc).__name__


def _domain_subdomain_regex(domain: str) -> str:
    """Ported verbatim from
    ``network_config/renderers.py::_domain_subdomain_regex`` -- the real
    RouterOS ``/ip dns static ... regexp=`` pattern matching every
    subdomain of ``domain`` (never ``domain`` itself; a second, exact-name
    ``/ip dns static`` entry covers that -- see
    ``configure_content_filter_rule``'s own docstring)."""
    escaped = domain.replace(".", r"\.")
    return f"^.*\\.{escaped}$"


def _routeros_seconds(value: object) -> int | None:
    """A RouterOS duration in seconds, or ``None`` if it is not one.

    RouterOS accepts ``600s`` on write and answers the read with ``10m``.
    Comparing the two as strings can never match, so a write guarded by
    ``row.get(key) != value`` re-issues its ``set`` on **every** push,
    forever -- the exact defect this file already documents fixing for
    ``disabled``, in a field nobody re-checked. Observed on real hardware:
    a DHCP server push issued ``set lease-time=600s`` on every call.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    total, number = 0, ""
    for char in text:
        if char.isdigit():
            number += char
        elif char in units and number:
            total += int(number) * units[char]
            number = ""
        else:
            return None
    if number:  # a bare count of seconds, e.g. "600"
        total += int(number)
    return total


def _same_routeros_duration(current: object, wanted: object) -> bool:
    """Whether two RouterOS durations mean the same span of time."""
    a, b = _routeros_seconds(current), _routeros_seconds(wanted)
    return a is not None and a == b


def _same_routeros_path(current: object, wanted: object) -> bool:
    """Whether two RouterOS file paths name the same directory.

    ``html-directory=cloudguest-hotspot`` is stored and read back as
    ``flash/cloudguest-hotspot`` on a device with flash storage -- observed
    on real hardware. Same consequence as the duration case: a pointless
    ``set`` on every push. Compared on the trailing segment, which is the
    part this platform chooses; the prefix is the device's own storage
    layout.
    """
    if current is None or wanted is None:
        return False
    return (
        str(current).strip("/").split("/")[-1]
        == str(wanted).strip("/").split("/")[-1]
    )


def _is_truthy(value: object) -> bool:
    """RouterOS booleans, read back honestly.

    The API answers a read with a real ``bool``, but accepts ``"no"``/
    ``"yes"``/``"true"``/``"false"`` on write, and a fake or an older
    firmware may hand back either shape. Comparing the raw value against a
    string is how an idempotent write turns into an update issued on every
    single push.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes"}


def _split_valid_servers(value: object) -> tuple[str, ...]:
    """A RouterOS ``valid-server`` list, split and canonicalized.

    Entries that are real MAC addresses come back in
    :func:`normalize_mac_address`'s canonical uppercase form. Anything
    else is kept **verbatim rather than dropped**: a reader that silently
    discards what it cannot parse reports a shorter trusted list than the
    device actually has, which on this field means telling an operator a
    server is untrusted while the router happily accepts it.
    """
    if value is None:
        return ()
    if isinstance(value, list | tuple):
        parts = [str(item) for item in value]
    else:
        parts = str(value).split(",")
    servers: list[str] = []
    for part in parts:
        text = part.strip()
        if not text:
            continue
        servers.append(normalize_mac_address(text) or text)
    return tuple(servers)


def _same_valid_servers(current: object, wanted: tuple[str, ...]) -> bool:
    """Whether the device already trusts exactly these DHCP servers.

    Compared as a *set of canonicalized entries*, never as the raw string.
    RouterOS answers with its own uppercase form and in its own order, so
    a caller that supplied a lowercase MAC -- or the same two servers the
    other way round -- would differ on every single read and this writer
    would re-issue the identical ``set`` forever. That is the string-
    compare trap :func:`_is_truthy` exists for on ``disabled`` and
    :func:`_routeros_seconds` on durations, in a third field with a third
    shape.
    """
    return set(_split_valid_servers(current)) == set(wanted)


_RATE_SUFFIX_MULTIPLIERS = {"k": 1_000, "m": 1_000_000, "g": 1_000_000_000}


def _rate_to_bps(value: object) -> int | None:
    """RouterOS rate fields, read back honestly -- :func:`_is_truthy`'s
    sibling for numbers.

    ``max-limit=0k`` is what goes out on the wire and ``0`` is what comes
    back; ``1000k`` goes out and ``1000000`` comes back. Comparing the raw
    values as strings is how an idempotent write turns into an update
    issued on every single push. Returns ``None`` for anything that is not
    a rate, so a caller can fall back to comparing it some other way rather
    than silently treating two unparseable values as equal.
    """
    text = str(value).strip().lower()
    if not text:
        return None
    multiplier = 1
    if text[-1] in _RATE_SUFFIX_MULTIPLIERS:
        multiplier = _RATE_SUFFIX_MULTIPLIERS[text[-1]]
        text = text[:-1]
    try:
        return int(float(text) * multiplier)
    except ValueError:
        return None


def _queue_tree_field_differs(field: str, current: object, desired: str) -> bool:
    """Whether a ``/queue tree`` row's field really differs from what is
    wanted, comparing each field in the shape RouterOS answers reads in
    rather than as raw text. See :meth:`MikroTikAdapter.create_queue_tree`.
    """
    if field == "max-limit":
        current_bps, desired_bps = _rate_to_bps(current), _rate_to_bps(desired)
        if current_bps is not None and desired_bps is not None:
            return current_bps != desired_bps
    if field == "priority":
        # RouterOS answers an integer field with an int on some firmware and
        # a string on others; the write is always a string.
        try:
            return int(str(current)) != int(desired)
        except (TypeError, ValueError):
            pass
    return str(current if current is not None else "") != desired


def _smallest_enclosing_network(
    start: str, end: str
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Ported verbatim from
    ``network_config/renderers.py::_smallest_enclosing_network`` -- the
    smallest real CIDR block guaranteed to contain both bounds, computed
    exactly (never a fabricated conventional mask). See that module's own
    docstring for the full "DHCP subnet-mask gap" rationale this exists
    to honestly handle: ``DhcpPoolConfig`` (like the ``DhcpPool`` model it
    mirrors) carries a range, not a CIDR."""
    start_ip = ipaddress.ip_address(start)
    end_ip = ipaddress.ip_address(end)
    for prefix_len in range(start_ip.max_prefixlen, -1, -1):
        candidate = ipaddress.ip_network(f"{start_ip}/{prefix_len}", strict=False)
        if start_ip in candidate and end_ip in candidate:
            return candidate
    return ipaddress.ip_network(f"{start_ip}/0", strict=False)


class MikroTikAdapter:
    """See module docstring for the full port-not-reinvent write-up."""

    vendor = DeviceVendor.MIKROTIK

    # ------------------------------------------------------------------
    # connection helpers
    # ------------------------------------------------------------------

    def _connect_api(self, creds: DeviceCredentials):  # noqa: ANN202
        try:
            return librouteros.connect(
                host=creds.host,
                username=creds.username,
                password=creds.secret,
                port=creds.port or _DEFAULT_API_PORT,
                timeout=creds.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise MikroTikConnectionError(creds.host, _describe_exception(exc)) from exc

    def _ssh_port(self, creds: DeviceCredentials) -> int:
        return _safe_int(creds.extra.get("ssh_port"), default=_DEFAULT_SSH_PORT) or (
            _DEFAULT_SSH_PORT
        )

    def _ssh_connect(self, creds: DeviceCredentials):  # noqa: ANN202
        """Shared SSH-connect helper for the provisioning-engine methods
        below (``push_config``/``verify_config``/``backup``/``restore``/
        ``upload_file``/``execute_raw_command``) -- ported from
        ``provisioning_engine/device_adapters.py::_ssh_connect``. Distinct
        from ``provision_device``'s own inline ``asyncssh.connect`` call
        (that one predates this helper and is left untouched)."""
        return asyncssh.connect(
            creds.host,
            port=self._ssh_port(creds),
            username=creds.username,
            password=creds.secret,
            known_hosts=None,
            connect_timeout=creds.timeout_seconds,
        )

    async def _run_ssh_command(self, creds: DeviceCredentials, command: str) -> None:
        """Ported from
        ``provisioning_engine/device_adapters.py::_run_ssh_command``."""
        try:
            async with self._ssh_connect(creds) as conn:
                result = await conn.run(command, check=False)
        except (OSError, asyncssh.Error) as exc:
            raise MikroTikConnectionError(creds.host, _describe_exception(exc)) from exc
        if result.exit_status != 0:
            raise MikroTikDeviceError(
                creds.host,
                f"{command}: {result.stderr or f'exit status {result.exit_status}'}",
            )

    async def _download_file_via_sftp(
        self, creds: DeviceCredentials, filename: str
    ) -> bytes:
        """Ported from
        ``provisioning_engine/device_adapters.py::_download_file``."""
        try:
            async with (
                self._ssh_connect(creds) as conn,
                conn.start_sftp_client() as sftp,
                sftp.open(filename, "rb") as remote_file,
            ):
                return await remote_file.read()
        except (OSError, asyncssh.Error) as exc:
            raise MikroTikConnectionError(creds.host, _describe_exception(exc)) from exc

    # ------------------------------------------------------------------
    # discovery / telemetry (read-only)
    # ------------------------------------------------------------------

    async def get_interface_list(self, creds: DeviceCredentials) -> list[InterfaceInfo]:
        """Ported from ``router/device_adapters.py::_list_sync``. Filters
        out ``lo``, any interface already bound to a ``/ip dhcp-server``,
        and any interface that is a ``/ip dhcp-client`` -- an interface
        that can only fail on submit is never offered at all (see that
        module's own docstring)."""
        return await asyncio.to_thread(self._get_interface_list_sync, creds)

    def _get_interface_list_sync(self, creds: DeviceCredentials) -> list[InterfaceInfo]:
        api = self._connect_api(creds)
        try:
            try:
                interfaces = list(api.path("interface"))
                bridge_ports = list(api.path("interface", "bridge", "port"))
                addresses = list(api.path("ip", "address"))
                dhcp_servers = list(api.path("ip", "dhcp-server"))
                dhcp_clients = list(api.path("ip", "dhcp-client"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, _describe_exception(exc)) from exc
        finally:
            api.close()

        bridge_of: dict[str, str] = {
            str(p.get("interface")): str(p.get("bridge"))
            for p in bridge_ports
            if p.get("interface") and p.get("bridge")
        }
        has_ip: set[str] = {str(a.get("interface")) for a in addresses if a.get("interface")}
        has_dhcp_server: set[str] = {
            str(d.get("interface")) for d in dhcp_servers if d.get("interface")
        }
        has_dhcp_client: set[str] = {
            str(d.get("interface")) for d in dhcp_clients if d.get("interface")
        }

        result: list[InterfaceInfo] = []
        for row in interfaces:
            name = row.get("name")
            if not name:
                continue
            name = str(name)
            if name == "lo":
                continue
            if name in has_dhcp_server or name in has_dhcp_client:
                continue
            result.append(
                InterfaceInfo(
                    name=name,
                    type=str(row.get("type")) if row.get("type") else None,
                    running=bool(row.get("running", False)),
                    disabled=bool(row.get("disabled", False)),
                    bridge=bridge_of.get(name),
                    has_ip_address=name in has_ip,
                    is_bridge_port=name in bridge_of,
                    mac_address=(
                        str(row.get("mac-address"))
                        if row.get("mac-address")
                        else None
                    ),
                )
            )
        return result

    async def read_network_snapshot(self, creds: DeviceCredentials) -> NetworkSnapshot:
        """Every interface and every ``/ip address`` on the device, in one
        connection, filtered by nothing but ``lo``.

        Not a variant of :meth:`get_interface_list` and not replaceable by
        it. That method exists to back a DHCP picker, so it drops every
        interface already bound to an ``/ip dhcp-server`` -- and on a real
        router (verified on the lab hEX) that drops ``bridge``, which is
        precisely the interface a VLAN trunk hangs off. Reusing it for a
        VLAN form hides the one answer the form needs.

        The ``/ip address`` half is here rather than in a second method
        because it is read for the same reason at the same moment: a VLAN
        push has to know whether the subnet it is about to claim already
        exists on this device before it writes anything, and "reachable",
        "interface exists" and "subnet free" are one round trip, not three
        that can disagree with each other.
        """
        return await asyncio.to_thread(self._read_network_snapshot_sync, creds)

    def _read_network_snapshot_sync(self, creds: DeviceCredentials) -> NetworkSnapshot:
        api = self._connect_api(creds)
        try:
            try:
                interfaces = list(api.path("interface"))
                bridge_ports = list(api.path("interface", "bridge", "port"))
                addresses = list(api.path("ip", "address"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, _describe_exception(exc)) from exc
        finally:
            api.close()

        bridge_of: dict[str, str] = {
            str(p.get("interface")): str(p.get("bridge"))
            for p in bridge_ports
            if p.get("interface") and p.get("bridge")
        }
        has_ip: set[str] = {
            str(a.get("interface")) for a in addresses if a.get("interface")
        }

        listed: list[InterfaceInfo] = []
        for row in interfaces:
            raw_name = row.get("name")
            if not raw_name:
                continue
            name = str(raw_name)
            if name == "lo":
                continue
            listed.append(
                InterfaceInfo(
                    name=name,
                    type=str(row.get("type")) if row.get("type") else None,
                    running=_is_truthy(row.get("running", False)),
                    disabled=_is_truthy(row.get("disabled", False)),
                    bridge=bridge_of.get(name),
                    has_ip_address=name in has_ip,
                    is_bridge_port=name in bridge_of,
                    mac_address=(
                        str(row.get("mac-address"))
                        if row.get("mac-address")
                        else None
                    ),
                )
            )
        return NetworkSnapshot(
            interfaces=listed,
            ip_addresses=[
                IpAddressInfo(
                    address=str(row["address"]),
                    interface=str(row["interface"]) if row.get("interface") else None,
                    disabled=_is_truthy(row.get("disabled", False)),
                    invalid=_is_truthy(row.get("invalid", False)),
                )
                for row in addresses
                if row.get("address")
            ],
        )

    async def get_wan_health(self, creds: DeviceCredentials, *, target_ip: str) -> WanHealth:
        """Composes three real, independently-audited read operations from
        ``isp/device_adapters.py`` into the one vendor-agnostic
        ``WanHealth`` shape:

        * ``ping`` (``/tool/ping``) -> ``reachable``/``latency_ms``/
          ``packet_loss_percent``.
        * ``get_active_default_gateway`` (``/ip/route``, never filtered by
          interface name -- see that method's own docstring, including its
          dynamic-route-or-active-static-route fallback) ->
          ``dynamic_gateway`` (name unchanged for shape stability, though
          the value may now come from a static route -- see
          :func:`_select_default_route`), and incidentally the WAN-facing
          interface name RouterOS itself associates with that route.
        * ``get_pppoe_interface_status``/traffic counters, resolved against
          that same interface name when the router reports one, with the
          original's single-candidate stale-name fallback preserved when
          it doesn't exactly match any real ``/interface/pppoe-client``
          row.

        The original per-domain methods each took an explicit
        ``interface_name`` (from a stored ``IspLink.interface`` column);
        the vendor-agnostic contract has no such field (not every vendor
        has an "interface" concept), so this port derives the interface to
        inspect from the router's own live routing table instead of a
        possibly-stale stored value -- an honest adaptation, not a
        behavior change to the underlying RouterOS reads themselves.
        """
        return await asyncio.to_thread(self._get_wan_health_sync, creds, target_ip)

    def _get_wan_health_sync(self, creds: DeviceCredentials, target_ip: str) -> WanHealth:
        api = self._connect_api(creds)
        try:
            try:
                ping_rows = list(api("/tool/ping", address=target_ip, count="4"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"ping failed: {exc}") from exc

            try:
                route_rows = list(api.path("ip", "route"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"read /ip/route failed: {exc}"
                ) from exc

            try:
                pppoe_rows = list(api.path("interface", "pppoe-client"))
            except LibRouterosError:
                pppoe_rows = []

            try:
                interface_rows = list(api.path("interface"))
            except LibRouterosError:
                interface_rows = []
        finally:
            api.close()

        sent, received, packet_loss, avg_rtt_ms = _parse_ping_rows(
            ping_rows, requested_count=4
        )

        dynamic_gateway, wan_interface = _select_default_route(route_rows)

        ppp_status: bool | None = None
        pppoe_interface_name = wan_interface
        pppoe_row = None
        if pppoe_rows:
            pppoe_row = next(
                (r for r in pppoe_rows if r.get("name") == wan_interface), None
            )
            if pppoe_row is None and len(pppoe_rows) == 1:
                # Same stale-interface-name single-candidate fallback as
                # isp/device_adapters.py::_get_pppoe_interface_status_sync
                # -- exactly one real PPPoE client interface exists, so
                # that's almost certainly the one we mean even though it
                # doesn't match the name derived from the route table.
                logger.warning(
                    "mikrotik_pppoe_interface_name_mismatch_fallback",
                    extra={
                        "requested_interface": wan_interface,
                        "actual_interface": pppoe_rows[0].get("name"),
                    },
                )
                pppoe_row = pppoe_rows[0]
                pppoe_interface_name = _safe_str(pppoe_row.get("name"))
            if pppoe_row is not None:
                running = str(pppoe_row.get("running", "false")).lower() == "true"
                disabled = str(pppoe_row.get("disabled", "false")).lower() == "true"
                ppp_status = running and not disabled

        rx_bytes: int | None = None
        tx_bytes: int | None = None
        traffic_interface = pppoe_interface_name or wan_interface
        if traffic_interface is not None:
            row = next(
                (r for r in interface_rows if r.get("name") == traffic_interface), None
            )
            if row is not None:
                rx_bytes = _safe_int(row.get("rx-byte"), default=0)
                tx_bytes = _safe_int(row.get("tx-byte"), default=0)

        return WanHealth(
            reachable=received > 0,
            dynamic_gateway=dynamic_gateway,
            ppp_status=ppp_status,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            latency_ms=avg_rtt_ms,
            packet_loss_percent=packet_loss,
        )

    async def list_connected_devices(self, creds: DeviceCredentials) -> list[ConnectedDevice]:
        """Ported from
        ``connected_devices/device_adapters.py::_discover_sync`` /
        ``_merge_discovered_devices`` -- merges DHCP-lease/ARP/wireless-
        registration-table replies into one row per MAC. Each menu is
        queried independently (``_safe_query``): a wired-only router with
        no wireless package at all has no
        ``interface wireless registration-table`` menu, and that alone
        must never abort discovery of the wired devices the other two
        menus already carry fine (see that module's own docstring)."""
        return await asyncio.to_thread(self._list_connected_devices_sync, creds)

    def _safe_query(self, api, *path: str) -> list[dict[str, object]]:  # noqa: ANN001
        try:
            return list(api.path(*path))
        except LibRouterosError as exc:
            logger.info(
                "mikrotik_connected_devices_menu_unavailable",
                extra={"menu": "/".join(path), "detail": str(exc)},
            )
            return []

    def _list_connected_devices_sync(
        self, creds: DeviceCredentials
    ) -> list[ConnectedDevice]:
        api = self._connect_api(creds)
        try:
            leases = self._safe_query(api, "ip", "dhcp-server", "lease")
            arp_entries = self._safe_query(api, "ip", "arp")
            wireless_entries = self._safe_query(
                api, "interface", "wireless", "registration-table"
            )
        finally:
            api.close()
        return _merge_connected_devices(leases, arp_entries, wireless_entries)

    async def disconnect_device(
        self, creds: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        """Ported from
        ``connected_devices/device_adapters.py::_disconnect_sync`` -- a
        real, but partial, action: a real wireless "kick" (forces
        re-association) if the device is currently in the wireless
        registration table, plus best-effort ARP/DHCP-lease removal. There
        is no equivalent forced disconnect for an already-established wired
        link (see that module's own docstring for why this is a genuine,
        honest limitation). ``interface`` is accepted for Protocol/API
        symmetry but -- exactly like the original -- is not used to filter
        the search; both menus are searched by MAC address alone."""
        await asyncio.to_thread(self._disconnect_device_sync, creds, mac_address)

    def _disconnect_device_sync(self, creds: DeviceCredentials, mac_address: str) -> None:
        """Best-effort wireless kick, then an unconditional DHCP-lease
        removal -- kept as two independent try/except blocks (mirroring
        ``_list_connected_devices_sync``/``_safe_query``'s own per-menu
        isolation) so a wired-only router (hEX lite/hEX/RB750-class, no
        wireless package at all -- a real, confirmed deployment) doesn't
        abort the whole operation just because the wireless menu doesn't
        exist. Previously both steps shared one try/except here, so that
        exact, common real hardware always failed with "no such command or
        directory (wireless)" even though the DHCP-lease removal below --
        the part that actually matters for a wired device -- would have
        succeeded on its own. See
        ``connected_devices/device_adapters.py::_disconnect_sync`` for the
        original fix this ports."""
        api = self._connect_api(creds)
        try:
            try:
                wireless_menu = api.path("interface", "wireless", "registration-table")
                for row in wireless_menu:
                    if normalize_mac_address(row.get("mac-address")) == mac_address:
                        wireless_menu.remove(row.get(".id"))
                        break
            except LibRouterosError as exc:
                logger.info(
                    "mikrotik_disconnect_wireless_kick_unavailable",
                    extra={"host": creds.host, "mac_address": mac_address, "detail": str(exc)},
                )
            try:
                dhcp_menu = api.path("ip", "dhcp-server", "lease")
                for row in dhcp_menu:
                    if normalize_mac_address(row.get("mac-address")) == mac_address:
                        dhcp_menu.remove(row.get(".id"))
                        break
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"disconnect_device: {exc}") from exc
        finally:
            api.close()

    # ------------------------------------------------------------------
    # hotspot session control (guest_access blocklist enforcement)
    # ------------------------------------------------------------------

    async def read_hotspot_session_control(
        self, creds: DeviceCredentials
    ) -> HotspotSessionControl:
        """Reads, from the device, whether it runs a hotspot at all and
        whether it currently accepts an RFC 5176 Disconnect-Request.

        **Why this is a read and never an assumption.** Both places this
        codebase writes ``/radius incoming`` -- this adapter's own
        :meth:`set_radius_client_config` and
        ``network_config/renderers.py``'s ``render_radius_client`` -- set
        ``accept=yes`` and ``port=3799`` in the *same* statement. The lab
        router nonetheless holds ``accept=false port=3799``: the port is
        the value this platform wrote (RouterOS's own default is 1700), so
        the write did land, and ``accept`` was reset afterwards by
        something nobody has identified. A platform that infers "we
        configured CoA, therefore CoA works" from its own history is
        wrong about that router today.

        ``accept`` is resolved through :func:`_is_truthy`, never a string
        compare: the API answers a read with a real ``bool`` and accepts
        ``"no"``/``"false"`` on write, so ``row.get("accept") == "yes"``
        would read a live ``True`` as disabled.

        Read-only -- this method never writes to ``/radius incoming``. See
        :meth:`end_hotspot_sessions` for why repairing it is deliberately
        not part of the enforcement path.
        """
        return await asyncio.to_thread(self._read_hotspot_session_control_sync, creds)

    def _hotspot_session_control(self, api, host: str) -> HotspotSessionControl:  # noqa: ANN001
        try:
            hotspot_servers = len(list(api.path("ip", "hotspot")))
        except LibRouterosError as exc:
            raise MikroTikDeviceError(
                host, f"read_hotspot_session_control: {exc}"
            ) from exc
        coa_accept = False
        coa_port: int | None = None
        try:
            for row in api.path("radius", "incoming"):
                coa_accept = _is_truthy(row.get("accept"))
                coa_port = _safe_int(row.get("port"))
                break
        except LibRouterosError as exc:
            # A router with no ``/radius incoming`` menu at all cannot
            # accept a Disconnect either. Reported as "no", logged, never
            # raised -- the caller's real mechanism does not depend on it.
            logger.info(
                "mikrotik_radius_incoming_unreadable",
                extra={"host": host, "detail": str(exc)},
            )
        return HotspotSessionControl(
            hotspot_servers=hotspot_servers,
            coa_accept=coa_accept,
            coa_port=coa_port,
        )

    def _read_hotspot_session_control_sync(
        self, creds: DeviceCredentials
    ) -> HotspotSessionControl:
        api = self._connect_api(creds)
        try:
            return self._hotspot_session_control(api, creds.host)
        finally:
            api.close()

    async def end_hotspot_sessions(
        self,
        creds: DeviceCredentials,
        *,
        mac_address: str | None,
        username: str | None,
    ) -> HotspotDisconnectResult:
        """Ends every live ``/ip hotspot active`` session belonging to one
        guest -- the operation that actually cuts them off.

        **Why device-local removal and not a RADIUS Disconnect-Request.**
        Both end a hotspot session; RouterOS's own response to a
        Disconnect-Request is to remove the host from this same table. The
        difference is what each one needs to work:

        * A Disconnect needs ``/radius incoming accept=yes`` (false on the
          lab router), needs the right shared secret and the right session
          identifiers or it is dropped with no NAK, and needs an *inbound*
          UDP path from this platform to the NAS. That path does not exist
          today -- see ``RadiusNasClient.ip_address``'s own comment in
          ``app/domains/guest/models.py``: the API container has no route
          into the hub's tunnel subnet, so ``issue_live_disconnect`` has
          been reporting "no response" fleet-wide rather than "never
          sent".
        * This needs port 8728, which is the transport every other write
          in this gateway already uses and the only one confirmed to reach
          fleet routers.

        So a Disconnect is the weaker mechanism *on this fleet*, and it
        fails silently where this one raises. CoA availability is still
        read and reported (:meth:`read_hotspot_session_control`), because
        an operator deserves to know that the RFC-sanctioned path is shut
        -- but the block does not depend on it.

        **``/radius incoming`` is deliberately not repaired here.** This
        method has every ingredient to issue
        ``api.path("radius", "incoming").update(accept="yes")`` and fix the
        contradiction it reads. It does not, for two reasons. Repairing it
        would not help the operation at hand -- the session is already
        being ended by the mechanism above -- so it would be an unrelated
        write to a live router's RADIUS configuration performed as a side
        effect of a customer clicking "Block". And a change to exactly
        this subsystem took the guest network down earlier today. A write
        that fixes nothing for the caller and can break everything for the
        venue does not belong on a customer-triggered path. The honest
        move is to surface ``coa_accept=False`` so an operator repairs it
        deliberately, through :meth:`set_radius_client_config`, which is
        the method that owns that setting.

        **Matching.** A row matches when its normalized ``mac-address``
        equals ``mac_address``, or its ``user`` equals ``username``
        exactly. Either identifier alone is enough, because either alone
        identifies the guest: the MAC is what the device knows them by,
        the ``user`` is what RADIUS authenticated. Both ``None`` matches
        **nothing** -- a block whose subject could not be identified must
        end zero sessions rather than every session on the router.

        **Removal is per-row by ``.id``**, never a bare ``remove [find]``:
        a predicate that evaluates to nothing must produce zero removals,
        and enumerating in Python is the only way to guarantee that.

        Idempotent: a guest with no live session matches nothing and
        raises nothing, so a retry after a partial failure -- or a second
        block of an already-blocked guest -- completes cleanly.
        """
        return await asyncio.to_thread(
            self._end_hotspot_sessions_sync, creds, mac_address, username
        )

    @staticmethod
    def _match_active_rows(
        rows: list[dict[str, object]],
        mac_address: str | None,
        username: str | None,
    ) -> tuple[HotspotActiveSession, ...]:
        if mac_address is None and username is None:
            return ()
        matched: list[HotspotActiveSession] = []
        for row in rows:
            row_mac = normalize_mac_address(row.get("mac-address"))
            row_user = _safe_str(row.get("user"))
            if (mac_address is not None and row_mac == mac_address) or (
                username is not None and row_user == username
            ):
                row_id = _safe_str(row.get(".id"))
                if row_id is None:
                    # A row with no ``.id`` cannot be removed per-row, and
                    # this method does not fall back to a broad remove.
                    continue
                matched.append(
                    HotspotActiveSession(
                        routeros_id=row_id,
                        user=row_user,
                        mac_address=row_mac,
                        address=_safe_str(row.get("address")),
                    )
                )
        return tuple(matched)

    def _end_hotspot_sessions_sync(
        self,
        creds: DeviceCredentials,
        mac_address: str | None,
        username: str | None,
    ) -> HotspotDisconnectResult:
        normalized_mac = (
            normalize_mac_address(mac_address) if mac_address is not None else None
        )
        api = self._connect_api(creds)
        try:
            control = self._hotspot_session_control(api, creds.host)
            try:
                menu = api.path("ip", "hotspot", "active")
                matched = self._match_active_rows(
                    list(menu), normalized_mac, username
                )
                for row in matched:
                    menu.remove(row.routeros_id)
                # A SECOND read, not a re-use of the first. Without it this
                # method could only report "the removes did not raise",
                # which is precisely the claim this platform has been
                # burned by twice.
                still_active = self._match_active_rows(
                    list(api.path("ip", "hotspot", "active")),
                    normalized_mac,
                    username,
                )
            except LibRouterosError as exc:
                # Unlike ``disconnect_device``'s optional wireless menu, an
                # unreadable ``/ip hotspot active`` is fatal here: without
                # it this method cannot tell whether the guest is still
                # online, and reporting success would be a guess.
                raise MikroTikDeviceError(
                    creds.host, f"end_hotspot_sessions: {exc}"
                ) from exc
        finally:
            api.close()
        return HotspotDisconnectResult(
            control=control,
            matched=matched,
            removed_ids=tuple(row.routeros_id for row in matched),
            still_active=still_active,
        )

    # ------------------------------------------------------------------
    # diagnostics (shared by network_diagnostics + isp call sites)
    # ------------------------------------------------------------------

    async def ping(
        self, creds: DeviceCredentials, *, target: str, count: int, timeout_seconds: int
    ) -> PingResult:
        """Ported from ``network_diagnostics/device_adapters.py::_ping_sync``
        and ``isp/device_adapters.py::_ping_sync`` -- both call sites issue
        the identical real RouterOS command
        (``api("/tool/ping", address=target, count=str(count))``) and parse
        the reply identically. ``timeout_seconds`` is accepted for Protocol
        parity with both originals but, exactly like both originals, is not
        itself used inside the ping command -- only ``creds.timeout_seconds``
        (used when opening the connection) matters, an existing, if slightly
        odd, real behavior preserved verbatim rather than "fixed" here."""
        return await asyncio.to_thread(self._ping_sync, creds, target, count)

    def _ping_sync(self, creds: DeviceCredentials, target: str, count: int) -> PingResult:
        api = self._connect_api(creds)
        try:
            try:
                rows = list(api("/tool/ping", address=target, count=str(count)))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"ping failed: {exc}") from exc
        finally:
            api.close()
        sent, received, packet_loss, avg_rtt_ms = _parse_ping_rows(
            rows, requested_count=count
        )
        return PingResult(
            sent=sent,
            received=received,
            packet_loss_percentage=packet_loss,
            avg_rtt_ms=avg_rtt_ms,
        )

    async def traceroute(
        self,
        creds: DeviceCredentials,
        *,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        """Ported from
        ``network_diagnostics/device_adapters.py::_traceroute_sync`` --
        RouterOS's own ``/tool/traceroute`` streams one reply row per
        completed probe, updating a given hop's cumulative stats across
        several rows before moving to the next hop.
        :func:`_parse_traceroute_rows` collapses consecutive same-
        ``address`` rows into one hop each, numbering hops by position in
        the reply stream."""
        return await asyncio.to_thread(
            self._traceroute_sync, creds, target, max_hops
        )

    def _traceroute_sync(
        self, creds: DeviceCredentials, target: str, max_hops: int
    ) -> TracerouteResult:
        api = self._connect_api(creds)
        try:
            try:
                rows = list(
                    api(
                        "/tool/traceroute",
                        address=target,
                        **{"max-hops": str(max_hops)},
                    )
                )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"traceroute failed: {exc}") from exc
        finally:
            api.close()
        return TracerouteResult(hops=_parse_traceroute_rows(rows))

    # ------------------------------------------------------------------
    # isp-specific WAN link telemetry
    # ------------------------------------------------------------------

    async def get_active_default_gateway(self, creds: DeviceCredentials) -> str | None:
        """Ported from
        ``isp/device_adapters.py::_get_active_default_gateway_sync``
        (renamed 2026-08-17 from ``get_dynamic_default_gateway`` -- see
        below) -- reads ``/ip/route`` and returns the router's own
        currently-usable ``0.0.0.0/0`` gateway. Prefers a genuinely
        *dynamic* default route (RouterOS's own live DHCP-negotiated
        gateway) when one exists; otherwise falls back to any other
        default route that is currently *active* (RouterOS's real,
        live "actually forwarding traffic right now" flag, which goes
        false the instant a ``check-gateway`` probe fails) and not
        administratively disabled -- see :func:`_select_default_gateway`
        for the full two-tier rule and the fleet-wide production incident
        (2026-08-17) that motivated the fallback tier. Deliberately never
        filtered by interface name (see module docstring)."""
        return await asyncio.to_thread(self._get_active_default_gateway_sync, creds)

    def _get_active_default_gateway_sync(self, creds: DeviceCredentials) -> str | None:
        api = self._connect_api(creds)
        try:
            try:
                rows = list(api.path("ip", "route"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"read_active_default_route: {exc}"
                ) from exc
        finally:
            api.close()
        return _select_default_gateway(rows)

    async def get_pppoe_interface_status(
        self, creds: DeviceCredentials, *, interface_name: str
    ) -> bool:
        """Ported from
        ``isp/device_adapters.py::_get_pppoe_interface_status_sync`` --
        reads ``/interface/pppoe-client`` and reports whether the named
        interface is up (``running`` and not ``disabled``). An exact-name
        miss falls back to the router's own single PPPoE interface when
        there is exactly one; genuine ambiguity (zero or multiple
        candidates with no exact match) raises
        :class:`MikroTikDeviceError` rather than guessing -- exactly the
        original's behavior."""
        return await asyncio.to_thread(
            self._get_pppoe_interface_status_sync, creds, interface_name
        )

    def _get_pppoe_interface_status_sync(
        self, creds: DeviceCredentials, interface_name: str
    ) -> bool:
        api = self._connect_api(creds)
        try:
            try:
                rows = list(api.path("interface", "pppoe-client"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"read_pppoe_interface_status: {exc}"
                ) from exc
        finally:
            api.close()
        row = next((r for r in rows if r.get("name") == interface_name), None)
        if row is None and len(rows) == 1:
            logger.warning(
                "mikrotik_pppoe_interface_name_mismatch_fallback",
                extra={
                    "requested_interface": interface_name,
                    "actual_interface": rows[0].get("name"),
                },
            )
            row = rows[0]
        if row is None:
            raise MikroTikDeviceError(
                creds.host,
                f"read_pppoe_interface_status: no PPPoE client interface named "
                f"'{interface_name}' found (and {len(rows)} candidates exist, "
                f"too ambiguous to guess)",
            )
        running = str(row.get("running", "false")).lower() == "true"
        disabled = str(row.get("disabled", "false")).lower() == "true"
        return running and not disabled

    async def get_interface_traffic_counters(
        self, creds: DeviceCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        """Ported from
        ``isp/device_adapters.py::_get_interface_traffic_counters_sync`` --
        reads ``/interface``'s own ``rx-byte``/``tx-byte`` fields for the
        named interface."""
        return await asyncio.to_thread(
            self._get_interface_traffic_counters_sync, creds, interface_name
        )

    def _get_interface_traffic_counters_sync(
        self, creds: DeviceCredentials, interface_name: str
    ) -> tuple[int, int] | None:
        api = self._connect_api(creds)
        try:
            try:
                rows = list(api.path("interface"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"read_interface_traffic_counters: {exc}"
                ) from exc
        finally:
            api.close()
        row = next((r for r in rows if r.get("name") == interface_name), None)
        if row is None:
            return None
        rx_bytes = _safe_int(row.get("rx-byte"), default=0)
        tx_bytes = _safe_int(row.get("tx-byte"), default=0)
        return rx_bytes, tx_bytes

    async def run_speed_test(
        self, creds: DeviceCredentials, *, download_url: str
    ) -> SpeedTestResult:
        """Issues a real RouterOS ``/tool/fetch`` download of
        ``download_url`` and computes genuine download throughput from the
        real bytes transferred and real wall-clock duration RouterOS itself
        reports -- never a simulated or estimated number.

        ## Why ``/tool/fetch``, not ``/tool/bandwidth-test``

        RouterOS's own ``/tool/bandwidth-test`` requires a RouterOS BTest
        server on the far end -- it cannot measure real throughput against
        the general internet, and was confirmed a dead end for this
        purpose (not even present as a REST endpoint on a real RouterOS
        7.16.2 hEX lite: ``{"detail":"no such command"}``). ``/tool/fetch``
        is RouterOS's real HTTP(S) downloader -- confirmed, against a real
        RouterOS 7.16.2 hEX lite router over its real WAN uplink, to
        genuinely fetch a file, report real cumulative
        ``downloaded``/``total`` (KiB) and ``duration`` fields as it goes,
        and finish with ``status: "finished"`` once complete. A 10MB fetch
        against ``https://speed.cloudflare.com/__down?bytes=10000000``
        against this project's real test router/Airtel DHCP link
        genuinely took 6 real seconds and transferred 9765 real KiB --
        ~13.3 Mbps, a real, repeatable measurement (5MB and 2MB fetches
        against the same link independently agreed, within noise).

        ## The one real precision caveat: whole-second duration only

        RouterOS's own ``/tool/fetch`` ``duration`` field only ever
        increments in whole seconds on this router/version (confirmed:
        even a 200KB fetch that must have completed in well under one
        real second still reported ``duration: "1s"``, never a
        sub-second value) -- this is a genuine device/command limitation,
        not a parsing gap, and it means very fast links measured with a
        small file will be *undercounted* (more real bytes than the
        rounded-up second implies), never overcounted. Callers should
        request a large enough ``download_url`` payload that the real
        transfer takes several real seconds, keeping that one-second
        rounding a small fraction of the total -- a caller-side sizing
        decision, not something this method can control given the URL is
        fully caller-specified. If the reported duration is not a real,
        positive number of seconds (e.g. the transfer never genuinely
        progressed), this method raises rather than fabricating a rate
        from a zero denominator.

        ## Upload: no real method exists

        There is no genuine, general-purpose "upload N bytes to a public
        endpoint and have RouterOS report the real duration" primitive on
        this device the way ``/tool/fetch`` provides for download -- this
        method deliberately measures download only. See
        :class:`~.contract.SpeedTestResult`'s own docstring.

        ## Real cleanup, not a real disk leak

        ``/tool/fetch`` with a ``dst-path`` genuinely writes the
        downloaded bytes to the router's own flash storage -- a real
        concern on this hardware class (the actual test router has only
        16MB total flash). This method always removes the downloaded file
        via a real ``/file remove`` afterward, in a ``finally``, whether
        the fetch succeeded or failed -- confirmed against the real
        router that no stray file is left behind either way.
        """
        return await asyncio.to_thread(self._run_speed_test_sync, creds, download_url)

    def _run_speed_test_sync(
        self, creds: DeviceCredentials, download_url: str
    ) -> SpeedTestResult:
        filename = f"wyfy-speedtest-{uuid.uuid4().hex[:10]}.tmp"
        mode = "https" if download_url.lower().startswith("https") else "http"
        api = self._connect_api(creds)
        try:
            try:
                rows = list(
                    api(
                        "/tool/fetch",
                        url=download_url,
                        mode=mode,
                        **{"dst-path": filename, "check-certificate": "no"},
                    )
                )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"run_speed_test: {exc}"
                ) from exc
            finally:
                # Real cleanup regardless of outcome -- see docstring's
                # "Real cleanup, not a real disk leak" section.
                try:
                    file_menu = api.path("file")
                    for row in file_menu:
                        if row.get("name") == filename:
                            file_menu.remove(row.get(".id"))
                            break
                except LibRouterosError:
                    logger.warning(
                        "mikrotik_speed_test_cleanup_failed",
                        extra={"host": creds.host, "filename": filename},
                    )
        finally:
            api.close()

        if not rows:
            raise MikroTikDeviceError(
                creds.host, "run_speed_test: no reply from /tool/fetch"
            )
        last = rows[-1]
        status = str(last.get("status", ""))
        if status != "finished":
            raise MikroTikDeviceError(
                creds.host,
                f"run_speed_test: fetch did not complete (status={status!r})",
            )
        downloaded_kib = _safe_int(last.get("downloaded"), default=None)
        if downloaded_kib is None or downloaded_kib <= 0:
            raise MikroTikDeviceError(
                creds.host, "run_speed_test: no real bytes were downloaded"
            )
        duration_ms = _parse_routeros_duration_ms(last.get("duration"))
        duration_seconds = duration_ms / 1000.0 if duration_ms else 0.0
        if duration_seconds <= 0:
            raise MikroTikDeviceError(
                creds.host,
                "run_speed_test: reported duration too short to measure a "
                "real rate (transfer finished in under RouterOS's own "
                "one-second reporting granularity) -- request a larger "
                "download_url payload",
            )
        downloaded_bytes = downloaded_kib * 1024
        download_mbps = (downloaded_bytes * 8) / duration_seconds / 1_000_000
        return SpeedTestResult(
            download_mbps=round(download_mbps, 2),
            downloaded_bytes=downloaded_bytes,
            duration_seconds=duration_seconds,
            test_url=download_url,
        )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def reboot_device(self, creds: DeviceCredentials) -> None:
        """Ported from ``router/device_adapters.py::_reboot_sync``. Issues
        a real ``/system reboot`` -- the device drops the connection the
        instant it accepts the command (it's already restarting), so a
        connection-reset/timeout on read here is the *expected* success
        case, not a failure: there is no "reboot accepted" acknowledgment a
        device that's already powering down could ever send back. Only a
        failure to even *open* the connection (bad credentials,
        unreachable host) is a real error."""
        await asyncio.to_thread(self._reboot_device_sync, creds)

    def _reboot_device_sync(self, creds: DeviceCredentials) -> None:
        api = self._connect_api(creds)
        try:
            try:
                tuple(api.path("system", "reboot")())
            except (LibRouterosError, OSError, EOFError):
                # The device disconnected mid-command -- exactly what a
                # real reboot looks like from the caller's side.
                pass
        finally:
            try:
                api.close()
            except (LibRouterosError, OSError, EOFError):
                pass

    async def provision_device(
        self, creds: DeviceCredentials, *, rendered_config: str, content_type: str
    ) -> ProvisionResult:
        """Ported from
        ``provisioning_engine/device_adapters.py::push_config``/
        ``upload_file`` -- uploads ``rendered_config`` via SFTP and applies
        it with a real RouterOS ``/import`` console command over SSH (the
        RouterOS API protocol has no file-transfer or file-system-level
        ``/import`` primitive of its own; see module docstring for the
        full "why SSH, not just the API" reasoning ported from that
        module). ``content_type`` is accepted for Protocol/parity with
        ``router_provisioning.adapters``'s existing ``build_job_payload``
        field but is not branched on here -- Phase 1 has exactly one real
        vendor and one real content type (``"routeros_script"``); a second
        content type would need a second real code path, not a silent
        guess."""
        try:
            import asyncssh  # local import: only provision_device needs SSH
        except ImportError as exc:  # pragma: no cover - dependency always declared
            return ProvisionResult(
                success=False,
                applied_content_summary=None,
                error_message=f"asyncssh not installed: {exc}",
            )

        filename = "wyfy-device-gateway-config.rsc"
        try:
            async with asyncssh.connect(
                creds.host,
                port=self._ssh_port(creds),
                username=creds.username,
                password=creds.secret,
                known_hosts=None,
                connect_timeout=creds.timeout_seconds,
            ) as conn:
                async with (
                    conn.start_sftp_client() as sftp,
                    sftp.open(filename, "wb") as remote_file,
                ):
                    await remote_file.write(rendered_config.encode("utf-8"))
                result = await conn.run(
                    f'/import file-name="{filename}"', check=False
                )
        except (OSError, asyncssh.Error) as exc:
            return ProvisionResult(
                success=False,
                applied_content_summary=None,
                error_message=_describe_exception(exc),
            )

        if result.exit_status not in (0, None):
            return ProvisionResult(
                success=False,
                applied_content_summary=None,
                error_message=str(result.stderr or f"exit status {result.exit_status}"),
            )
        return ProvisionResult(
            success=True,
            applied_content_summary=f"applied {len(rendered_config)} bytes via /import",
            error_message=None,
        )

    # ------------------------------------------------------------------
    # network config push
    # ------------------------------------------------------------------

    async def configure_vlan(self, creds: DeviceCredentials, *, vlan: VlanConfig) -> None:
        """Ported from ``network_config/renderers.py::render_vlan`` /
        ``_vlan_address_line`` -- same two real RouterOS operations
        (``/interface vlan add`` + ``/ip address add``), issued directly
        over the structured API (``Path.add``, mirroring
        ``queue_management.device_adapters``'s own write pattern) instead
        of as script text for an external agent. The RouterOS interface
        name is deterministically ``vlan{vlan_id}`` -- never
        ``vlan.name`` -- for exactly the reason documented in that
        module's own "VLAN: interface naming needs no invented identifier"
        section: ``vlan_id`` is the real, collision-free identity;
        ``vlan.name`` is carried through only as a human-readable
        comment."""
        await asyncio.to_thread(self._configure_vlan_sync, creds, vlan)

    def _configure_vlan_sync(self, creds: DeviceCredentials, vlan: VlanConfig) -> None:
        api = self._connect_api(creds)
        try:
            if vlan.port_mode == "access":
                self._configure_vlan_access(api, creds, vlan)
            else:
                self._configure_vlan_trunk(api, creds, vlan)
        finally:
            api.close()

    def _configure_vlan_trunk(
        self, api, creds: DeviceCredentials, vlan: VlanConfig
    ) -> None:
        """Tagged sub-interface on a parent trunk -- ``render_vlan``'s
        default branch."""
        vlan_interface = f"vlan{vlan.vlan_id}"
        try:
            if not self._interface_vlan_exists(api, vlan_interface):
                api.path("interface", "vlan").add(
                    name=vlan_interface,
                    **{"vlan-id": str(vlan.vlan_id)},
                    interface=vlan.interface,
                    comment=vlan.name,
                )
            self._ensure_ip_address(api, vlan.ip_cidr, vlan_interface)
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"configure_vlan: {exc}") from exc

    def _configure_vlan_access(
        self, api, creds: DeviceCredentials, vlan: VlanConfig
    ) -> None:
        """Dedicated untagged port -- ``render_vlan``'s "access" branch.

        The physical port is pulled out of the shared bridge and given the
        subnet directly. No ``/interface vlan`` entry is created: in this
        mode the VLAN is realized as a separate port, deliberately, so that
        enabling it can never disturb the shared production bridge's
        already-live traffic (see ``Vlan.port_mode``'s own docstring).
        """
        physical = vlan.interface
        try:
            for port in list(api.path("interface", "bridge", "port")):
                if port.get("interface") == physical:
                    api.path("interface", "bridge", "port").remove(port[".id"])
            self._ensure_ip_address(api, vlan.ip_cidr, physical)
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"configure_vlan: {exc}") from exc

    def _interface_vlan_exists(self, api, name: str) -> bool:
        return any(row.get("name") == name for row in api.path("interface", "vlan"))

    def _ensure_ip_address(self, api, ip_cidr: str | None, interface: str) -> None:
        """Adds the address only when that exact address is not already on
        that interface.

        Re-pushing is an ordinary operation -- an operator edits a name and
        saves again -- and RouterOS answers a duplicate ``add`` with
        "already have such item". Without this check the second push of an
        unchanged row surfaces as a device error, which teaches people to
        ignore push failures.

        Matches on address *and* interface: the same subnet existing
        somewhere else on the router is not this VLAN's address.
        """
        if not ip_cidr:
            return
        for row in api.path("ip", "address"):
            if row.get("address") == ip_cidr and row.get("interface") == interface:
                return
        api.path("ip", "address").add(address=ip_cidr, interface=interface)

    async def delete_vlan(
        self, creds: DeviceCredentials, *, vlan: VlanConfig
    ) -> None:
        """Removes what :meth:`configure_vlan` created, for the same
        ``port_mode``.

        Deleting a VLAN row never touched the device, and the gateway had
        no teardown method to call even if it had wanted to -- so a VLAN
        the platform created went on carrying traffic after the operator
        deleted it, with nothing in the UI to say so.

        Idempotent: removing what is already absent is a no-op, not an
        error. A delete retried after a partial failure completes cleanly,
        and deleting a row that was never pushed does nothing.
        """
        await asyncio.to_thread(self._delete_vlan_sync, creds, vlan)

    def _delete_vlan_sync(self, creds: DeviceCredentials, vlan: VlanConfig) -> None:
        api = self._connect_api(creds)
        try:
            try:
                if vlan.port_mode == "access":
                    self._delete_vlan_access(api, vlan)
                else:
                    self._delete_vlan_trunk(api, vlan)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"delete_vlan: {exc}") from exc
        finally:
            api.close()

    def _delete_vlan_trunk(self, api, vlan: VlanConfig) -> None:
        vlan_interface = f"vlan{vlan.vlan_id}"
        # Address first, then the interface carrying it. RouterOS would
        # cascade, but removing the address explicitly keeps the teardown
        # symmetric with the two writes configure_vlan made and leaves
        # nothing behind if the interface row is already gone.
        self._remove_ip_address(api, vlan.ip_cidr, vlan_interface)
        for row in list(api.path("interface", "vlan")):
            if row.get("name") == vlan_interface:
                api.path("interface", "vlan").remove(row[".id"])

    def _delete_vlan_access(self, api, vlan: VlanConfig) -> None:
        """Access mode gave a physical port the subnet directly, after
        pulling it out of the shared bridge.

        The address is removed, and the port is put back into
        ``vlan.previous_bridge`` when the caller recorded one.

        This used to deliberately leave the port unbridged, reasoning that
        which bridge it came from "was never recorded" and that rejoining a
        guessed one would be worse. Both halves of that were right; the
        conclusion was not. A venue's access point sat on an unbridged port
        with the guest network down, and the product had no way to undo what
        it had done -- an engineer restored it by hand. The fix was to record
        the bridge (see :class:`VlanConfig.previous_bridge`), not to keep
        declining to.

        Still no guessing: with ``previous_bridge`` unset the port is left
        out of every bridge exactly as before, because "in no bridge" is
        then the truthful previous state rather than an unknown one.

        ``pvid`` is copied from a sibling port of that same bridge rather
        than defaulted to 1 -- on a VLAN-filtering bridge the siblings'
        value is the one that makes untagged ingress land where the rest of
        that segment lands, and 1 would be a guess dressed as a default.
        """
        self._remove_ip_address(api, vlan.ip_cidr, vlan.interface)
        if not vlan.previous_bridge:
            return
        ports = list(api.path("interface", "bridge", "port"))
        if any(row.get("interface") == vlan.interface for row in ports):
            return  # already bridged -- somebody restored it first
        siblings = [
            row for row in ports if row.get("bridge") == vlan.previous_bridge
        ]
        pvid = str(siblings[0].get("pvid")) if siblings else "1"
        api.path("interface", "bridge", "port").add(
            interface=vlan.interface, bridge=vlan.previous_bridge, pvid=pvid
        )

    def _remove_ip_address(self, api, ip_cidr: str | None, interface: str) -> None:
        """Removes that exact address from that exact interface.

        Matches on address *and* interface, the same pair
        ``_ensure_ip_address`` adds on: the same subnet existing elsewhere
        on the router is not this VLAN's address and must not be removed.
        """
        if not ip_cidr:
            return
        for row in list(api.path("ip", "address")):
            if row.get("address") == ip_cidr and row.get("interface") == interface:
                api.path("ip", "address").remove(row[".id"])

    async def configure_vlan_hotspot(
        self, creds: DeviceCredentials, *, hotspot: VlanHotspotConfig
    ) -> None:
        """Puts a captive portal on one VLAN's own interface.

        Ported command-for-command from
        ``network_config/renderers.py::_render_vlan_hotspot`` -- the same
        six real RouterOS objects, in the same order, issued over the
        structured API instead of as script text:

        1. ``/ip pool`` -- the addresses the portal hands out.
        2. ``/ip dhcp-server`` on this VLAN's interface, drawing from it.
        3. ``/ip dhcp-server network`` -- gateway and DNS for the subnet,
           both the VLAN's own gateway address so guests resolve through
           the router that is about to intercept them.
        4. ``/ip hotspot profile`` -- ``hotspot-address``, the uploaded
           page set, and the ``dns-name`` RouterOS puts in its redirect.
        5. ``/ip dns static`` -- what makes that ``dns-name`` resolve.
           MikroTik's own documentation is explicit that ``dns-name``
           changes the redirect URL and does not by itself create a
           record; without this line guests are redirected to a hostname
           that answers NXDOMAIN.
        6. ``/ip hotspot`` -- the server, referencing 1 and 4.

        The order is the reference order and is not cosmetic: the hotspot
        server names the pool and the profile, and the DHCP server names
        the pool, so each must exist before the object that points at it.

        **Every write is existence-checked, and updates rather than skips
        when a mutable field changed.** Re-pushing is ordinary -- an
        operator edits a subnet and saves again -- and a portal whose pool
        still hands out the old subnet after a re-push is a portal that
        reports success and does not work.

        Nothing here touches the router's own default ``hotspot1`` or any
        other VLAN's portal: every object is named from ``vlan_id`` and
        bound to ``hotspot.interface``.
        """
        await asyncio.to_thread(self._configure_vlan_hotspot_sync, creds, hotspot)

    def _configure_vlan_hotspot_sync(
        self, creds: DeviceCredentials, hotspot: VlanHotspotConfig
    ) -> None:
        ranges = _hotspot_pool_range(hotspot.cidr, hotspot.gateway)
        if ranges is None:
            # Refused before the connection, not half-applied: a portal
            # with an empty pool accepts guests and hands out nothing.
            raise MikroTikDeviceError(
                creds.host,
                f"configure_vlan_hotspot: {hotspot.cidr} has no address left to "
                f"hand out once {hotspot.gateway} is reserved for the router",
            )
        names = _HotspotNames(hotspot.vlan_id)
        network = str(ipaddress.ip_network(hotspot.cidr, strict=False))
        api = self._connect_api(creds)
        try:
            try:
                self._ensure_ip_pool(api, names.pool, ranges)
                # No lease-time: _render_vlan_hotspot does not set one
                # either, and inventing one would change how long every
                # portal guest holds an address.
                self._ensure_dhcp_server(
                    api,
                    names.dhcp_server,
                    interface=hotspot.interface,
                    address_pool=names.pool,
                )
                self._ensure_dhcp_network(
                    api,
                    network,
                    {
                        "address": network,
                        "gateway": hotspot.gateway,
                        "dns-server": hotspot.gateway,
                    },
                    owner=names.network_owner,
                )
                self._ensure_hotspot_profile(
                    api,
                    names.profile,
                    hotspot_address=hotspot.gateway,
                    html_directory=hotspot.html_directory,
                    dns_name=hotspot.dns_name,
                )
                self._ensure_dns_static(
                    api,
                    hotspot.dns_name,
                    address=hotspot.gateway,
                    comment=names.dns_comment,
                )
                self._ensure_hotspot_server(
                    api,
                    names.server,
                    interface=hotspot.interface,
                    address_pool=names.pool,
                    profile=names.profile,
                )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_vlan_hotspot: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_hotspot_profile(
        self,
        api,
        name: str,
        *,
        hotspot_address: str,
        html_directory: str,
        dns_name: str,
    ) -> None:
        """Creates this VLAN's hotspot profile, or brings the existing one
        of that name into line.

        All three fields are things an operator can change -- re-address
        the VLAN, upload a new page set, rename the portal host -- so a
        found profile is updated, never skipped. Skipping is how a portal
        keeps redirecting to a gateway the VLAN no longer has.
        """
        desired = {
            "hotspot-address": hotspot_address,
            "html-directory": html_directory,
            "dns-name": dns_name,
            # Without these two the portal is decorative. RouterOS defaults
            # a new profile to `use-radius=no login-by=cookie,http-chap`,
            # so a per-VLAN portal came up unable to check a credential
            # against this platform at all: the page appeared, and no OTP,
            # voucher or password could ever succeed on it. Observed on the
            # lab router as `vlan95-hsprof use-radius=False`.
            #
            # The values mirror `hsprof1`, the router's own working guest
            # profile (`use-radius=True login-by=http-pap`) -- `http-pap`
            # because the portal posts the credential, which CHAP's
            # challenge flow does not carry. `radius-accounting` is left
            # alone: RouterOS turns it on by default once `use-radius=yes`.
            "use-radius": "yes",
            "login-by": "http-pap",
        }
        menu = api.path("ip", "hotspot", "profile")
        for row in menu:
            if row.get("name") != name:
                continue
            changed = {
                key: value
                for key, value in desired.items()
                # html-directory compared as a path: RouterOS stores
                # "cloudguest-hotspot" and reads back
                # "flash/cloudguest-hotspot".
                if not (
                    key == "html-directory"
                    and _same_routeros_path(row.get(key), value)
                )
                # use-radius answers a read as a real bool while accepting
                # "yes"/"no" on write, so a string compare never matches and
                # every push re-issues the same set. Same normalization trap
                # already documented on _ensure_dhcp_server's lease-time and
                # on `disabled`.
                and not (
                    key == "use-radius"
                    and _is_truthy(row.get(key)) is (value == "yes")
                )
                and row.get(key) != value
            }
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return
        menu.add(name=name, **desired)

    def _ensure_dns_static(
        self, api, name: str, *, address: str, comment: str
    ) -> None:
        """Creates the ``/ip dns static`` record that makes the profile's
        ``dns-name`` resolve, keyed on the name -- which is what RouterOS
        itself treats as this row's identity, and what a second ``add``
        collides on.

        ``disabled`` is normalized through :func:`_is_truthy`, never by
        string comparison: a disabled record answers nothing, so a
        re-push -- the operator asking for the portal again -- has to
        re-enable it, and comparing the raw value against ``"no"`` would
        instead issue a pointless update on every single push.
        """
        desired = {"address": address, "comment": comment}
        menu = api.path("ip", "dns", "static")
        for row in menu:
            if row.get("name") != name:
                continue
            changed = {
                key: value for key, value in desired.items() if row.get(key) != value
            }
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return
        menu.add(name=name, **desired, disabled="no")

    def _ensure_hotspot_server(
        self,
        api,
        name: str,
        *,
        interface: str,
        address_pool: str,
        profile: str,
    ) -> None:
        """Creates the ``/ip hotspot`` server itself, or corrects the one
        already carrying this VLAN's name.

        ``interface`` is part of the desired state rather than only of the
        ``add``: a server found by this VLAN's name but bound to another
        interface is this VLAN's portal challenging the wrong network,
        which is worth fixing where adding a second server beside it would
        not be.
        """
        desired = {
            "interface": interface,
            "address-pool": address_pool,
            "profile": profile,
        }
        menu = api.path("ip", "hotspot")
        for row in menu:
            if row.get("name") != name:
                continue
            changed = {
                key: value for key, value in desired.items() if row.get(key) != value
            }
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return
        menu.add(name=name, **desired, disabled="no")

    async def delete_vlan_hotspot(
        self, creds: DeviceCredentials, *, hotspot: VlanHotspotConfig
    ) -> None:
        """Takes one VLAN's captive portal back off the device.

        The exact reverse of :meth:`configure_vlan_hotspot`'s order, and
        that is a RouterOS requirement rather than a tidiness preference:
        the hotspot server holds the profile and the pool, and the DHCP
        server holds the pool, so RouterOS refuses to remove any of them
        while something still points at it.

        Idempotent, so it serves both intents that reach it -- the
        operator turned the portal off, or deleted the VLAN outright -- and
        a re-run after a partial failure completes cleanly.
        """
        await asyncio.to_thread(self._delete_vlan_hotspot_sync, creds, hotspot)

    def _delete_vlan_hotspot_sync(
        self, creds: DeviceCredentials, hotspot: VlanHotspotConfig
    ) -> None:
        names = _HotspotNames(hotspot.vlan_id)
        network = str(ipaddress.ip_network(hotspot.cidr, strict=False))
        api = self._connect_api(creds)
        try:
            try:
                self._remove_where(api, ("ip", "hotspot"), "name", names.server)
                self._remove_where(
                    api, ("ip", "dns", "static"), "name", hotspot.dns_name
                )
                self._remove_where(
                    api, ("ip", "hotspot", "profile"), "name", names.profile
                )
                # Only this portal's own row -- a DHCP pool on the same
                # subnet writes one keyed identically. See
                # _remove_dhcp_network.
                self._remove_dhcp_network(
                    api, network, owner=names.network_owner
                )
                self._remove_where(
                    api, ("ip", "dhcp-server"), "name", names.dhcp_server
                )
                self._remove_where(api, ("ip", "pool"), "name", names.pool)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"delete_vlan_hotspot: {exc}"
                ) from exc
        finally:
            api.close()

    async def delete_dhcp_pool(
        self, creds: DeviceCredentials, *, pool: DhcpPoolConfig
    ) -> None:
        """Removes the three objects :meth:`configure_dhcp_pool` created.

        Order matters and is not cosmetic: the DHCP server holds a
        reference to the address pool, so the server goes first or RouterOS
        refuses to remove a pool still in use.

        Idempotent, for the same reasons as :meth:`delete_vlan`.
        """
        await asyncio.to_thread(self._delete_dhcp_pool_sync, creds, pool)

    def _delete_dhcp_pool_sync(
        self, creds: DeviceCredentials, pool: DhcpPoolConfig
    ) -> None:
        identifier = re.sub(r"[^A-Za-z0-9_-]", "-", pool.interface)
        pool_name = f"{identifier}-pool"
        server_name = f"{identifier}-dhcp"
        network = str(
            _smallest_enclosing_network(pool.range_start, pool.range_end)
        )
        api = self._connect_api(creds)
        try:
            try:
                # Only our own row -- the per-VLAN portal writes a network
                # row for the same subnet, keyed identically by RouterOS.
                # Observed on hardware: this delete removed a live portal's
                # row, taking its gateway and DNS with it.
                self._remove_dhcp_network(
                    api, network, owner=f"WyfyGuest DHCP {identifier}"
                )
                # Server before pool: the server references the pool, and
                # RouterOS refuses to remove a pool that is still in use.
                self._remove_where(api, ("ip", "dhcp-server"), "name", server_name)
                self._remove_where(api, ("ip", "pool"), "name", pool_name)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"delete_dhcp_pool: {exc}"
                ) from exc
        finally:
            api.close()

    def _remove_where(
        self, api, path_segments: tuple[str, ...], field: str, value: str
    ) -> None:
        menu = api.path(*path_segments)
        for row in list(menu):
            if row.get(field) == value:
                menu.remove(row[".id"])

    def _remove_where_prefixed(
        self, api, path_segments: tuple[str, ...], field: str, prefix: str
    ) -> None:
        """:meth:`_remove_where`'s sibling for a field that carries an
        identity marker *and* a mutable tail -- a content-filtering
        comment, which is ``"<marker>: <the customer's label>"``. Matching
        the whole value would miss every rule renamed since its last push,
        which is precisely the rule this has to find.
        """
        menu = api.path(*path_segments)
        for row in list(menu):
            if str(row.get(field, "")).startswith(prefix):
                menu.remove(row[".id"])

    async def configure_dhcp_pool(
        self, creds: DeviceCredentials, *, pool: DhcpPoolConfig
    ) -> None:
        """Ported from
        ``network_config/renderers.py::render_dhcp_pool`` -- same three
        real RouterOS operations (``/ip pool add``, ``/ip dhcp-server
        add``, ``/ip dhcp-server network add``), issued directly over the
        structured API. ``DhcpPoolConfig`` carries a range, not a CIDR --
        the same gap that module's own docstring documents for
        ``DhcpPool`` -- so :func:`_smallest_enclosing_network` (ported
        verbatim) computes the real, minimal, honest CIDR block rather
        than fabricating a conventional ``/24``. Identifier naming is
        derived from ``pool.interface`` (this contract has no separate
        row-id/name field the way the original ``DhcpPool`` model does),
        so this assumes at most one DHCP pool per interface -- a
        reasonable simplification for the vendor-agnostic shape, not a
        silent behavior change to any RouterOS command itself."""
        await asyncio.to_thread(self._configure_dhcp_pool_sync, creds, pool)

    def _configure_dhcp_pool_sync(
        self, creds: DeviceCredentials, pool: DhcpPoolConfig
    ) -> None:
        identifier = re.sub(r"[^A-Za-z0-9_-]", "-", pool.interface)
        pool_name = f"{identifier}-pool"
        server_name = f"{identifier}-dhcp"
        network = _smallest_enclosing_network(pool.range_start, pool.range_end)
        api = self._connect_api(creds)
        try:
            try:
                # Each of the three writes is guarded on its own existence
                # check. All three were unconditional ``add`` calls, so the
                # second push of an unchanged pool died on RouterOS's
                # "already have such item" -- and re-pushing is an ordinary
                # operation (an operator widens a range and saves again).
                # Same fix, same reasoning as ``_ensure_ip_address`` above.
                # Checked before anything is created, not discovered
                # halfway through. RouterOS permits one dhcp-server per
                # interface; observed on hardware, the pool add succeeded,
                # the server add failed with "server or relay with such
                # interface already exists", and the pool was left orphaned
                # on the device with nothing referencing it while the
                # caller recorded a failed push.
                for existing in api.path("ip", "dhcp-server"):
                    if (
                        existing.get("interface") == pool.interface
                        and existing.get("name") != server_name
                    ):
                        raise MikroTikDeviceError(
                            creds.host,
                            f"configure_dhcp_pool: interface {pool.interface!r} "
                            f"already serves DHCP through "
                            f"{existing.get('name')!r}; RouterOS permits one "
                            "server per interface",
                        )
                self._ensure_ip_pool(
                    api, pool_name, f"{pool.range_start}-{pool.range_end}"
                )
                self._ensure_dhcp_server(
                    api,
                    server_name,
                    interface=pool.interface,
                    address_pool=pool_name,
                    lease_time=f"{pool.lease_time_seconds}s",
                )
                network_fields: dict[str, str] = {"address": str(network)}
                if pool.gateway:
                    network_fields["gateway"] = pool.gateway
                if pool.dns_servers:
                    network_fields["dns-server"] = ",".join(pool.dns_servers)
                self._ensure_dhcp_network(
                    api,
                    str(network),
                    network_fields,
                    owner=f"WyfyGuest DHCP {identifier}",
                )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_dhcp_pool: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_ip_pool(self, api, name: str, ranges: str) -> None:
        """Creates the address pool, or updates its ranges if a pool of that
        name is already there.

        Updating rather than skipping matters here in a way it does not for
        an IP address: the range *is* the thing an operator edits, so a
        re-push after widening a pool has to actually widen it on the
        device. Skipping would report success and leave the old range.
        """
        for row in api.path("ip", "pool"):
            if row.get("name") == name:
                if row.get("ranges") != ranges:
                    api.path("ip", "pool").update(**{".id": row[".id"], "ranges": ranges})
                return
        api.path("ip", "pool").add(name=name, ranges=ranges)

    def _ensure_dhcp_server(
        self,
        api,
        name: str,
        *,
        interface: str,
        address_pool: str,
        lease_time: str | None = None,
    ) -> None:
        """Creates the DHCP server, or brings an existing one of that name
        into line with the requested interface/pool/lease-time.

        ``lease_time`` is optional because one caller genuinely has none to
        state: ``_render_vlan_hotspot``'s own ``/ip dhcp-server add`` omits
        it and lets RouterOS apply its default, and passing a fabricated
        one here would change the lease behaviour of every captive portal
        this platform pushes. Omitted means "leave whatever the device
        has", not "set it to a default".
        """
        desired = {"interface": interface, "address-pool": address_pool}
        if lease_time is not None:
            desired["lease-time"] = lease_time
        for row in api.path("ip", "dhcp-server"):
            if row.get("name") == name:
                changed = {
                    key: value
                    for key, value in desired.items()
                    # lease-time compared as a duration, not a string:
                    # RouterOS stores "600s" and reads it back as "10m".
                    if not (
                        key == "lease-time"
                        and _same_routeros_duration(row.get(key), value)
                    )
                    and row.get(key) != value
                }
                # ``disabled`` is compared as a boolean, not a string.
                # RouterOS accepts "no"/"false" on write and answers reads
                # with a real bool, so a string comparison reports a
                # difference on every single push and issues a pointless
                # update forever.
                if _is_truthy(row.get("disabled")):
                    changed["disabled"] = "no"
                if changed:
                    api.path("ip", "dhcp-server").update(
                        **{".id": row[".id"], **changed}
                    )
                return
        api.path("ip", "dhcp-server").add(name=name, **desired, disabled="no")

    def _ensure_dhcp_network(
        self, api, address: str, fields: dict[str, str], *, owner: str
    ) -> None:
        """Creates the ``/ip dhcp-server network`` row for this subnet, or
        updates the existing row for that exact address.

        Matched on ``address`` because that is what RouterOS itself treats
        as the row's identity -- a second row for the same subnet is what
        produces "already have such item".

        ``owner`` is stamped into the row's ``comment`` and exists for the
        *delete* path, not this one. Two different features create a
        network row for the same subnet -- a DHCP pool and a per-VLAN
        captive portal both do -- and until this marker existed, deleting
        either one removed whichever row was there, because the delete
        matched on the subnet alone. Observed on real hardware: tearing
        down a DHCP pool silently removed a live portal's network row,
        taking its gateway and DNS with it. No error, no warning; the
        portal then hands out addresses with no way off the subnet.
        """
        stamped = {**fields, "comment": owner}
        for row in api.path("ip", "dhcp-server", "network"):
            if row.get("address") == address:
                changed = {
                    key: value
                    for key, value in stamped.items()
                    if row.get(key) != value
                }
                if changed:
                    api.path("ip", "dhcp-server", "network").update(
                        **{".id": row[".id"], **changed}
                    )
                return
        api.path("ip", "dhcp-server", "network").add(**stamped)

    def _remove_dhcp_network(self, api, address: str, *, owner: str) -> None:
        """Removes this subnet's network row **only if we wrote it**.

        A row for the same subnet that carries someone else's marker -- or
        no marker at all, meaning a human or an older build of this
        platform created it -- is left exactly where it is. Deleting one
        feature's configuration while tearing down another's is worse than
        leaving a stale row behind: the stale row is visible and
        correctable, the deletion is silent and breaks a running service.
        """
        menu = api.path("ip", "dhcp-server", "network")
        for row in list(menu):
            if row.get("address") == address and row.get("comment") == owner:
                menu.remove(row[".id"])

    # ------------------------------------------------------------------
    # rogue DHCP detection (/ip dhcp-server alert)
    # ------------------------------------------------------------------

    async def configure_rogue_dhcp_alerts(
        self, creds: DeviceCredentials, *, alerts: Sequence[RogueDhcpAlertConfig]
    ) -> None:
        """Converge ``/ip dhcp-server alert`` -- the device's own watch for
        a DHCP server on a guest segment that is not ours.

        ## A detector, and only ever a detector

        The alert **logs**; it drops nothing and blocks nothing. See
        :class:`RogueDhcpAlertConfig` for the full statement of that
        limit, and for the lab observation this exists because of. Nothing
        this method writes can interrupt a working guest network, which is
        the property that makes it safe to push to a fleet unattended.

        ## The interface is the row's identity

        Unlike the QoS/NAT/port-forward writers, this one is *not* keyed on
        a comment marker. RouterOS holds one alert per interface, and the
        interface is not a field a customer edits -- it is the segment
        being watched, which is the row's whole meaning. Keying on our own
        marker instead would mean an alert a human (or the hand-run probe
        that preceded this method) already placed on that interface is not
        recognized, and RouterOS would reject or duplicate around it. So an
        unmarked row on a watched interface is **adopted and stamped**,
        never duplicated -- ``_ensure_dhcp_network``'s reasoning, with the
        marker serving provenance rather than lookup.

        ## disabled=no is written explicitly, every time

        RouterOS creates an alert row **disabled by default**. Adding one
        without saying otherwise leaves a guard that is present in the
        configuration and watching nothing -- worse than no guard at all,
        because it reads as one. This was not theory: the first by-hand
        attempt on the lab router left exactly three such rows. So the
        ``add`` carries ``disabled="no"``, and an existing row found
        switched off is switched back on.

        ``disabled`` is compared through :func:`_is_truthy`, ``valid-server``
        through :func:`_same_valid_servers` and ``alert-timeout`` through
        :func:`_same_routeros_duration` -- three fields, three different
        ways the naive string compare would re-issue the same ``set`` on
        every push forever. See ``_ensure_dhcp_server`` for the first of
        those and why it matters.

        ## What is skipped, and what is refused

        An interface running no *enabled* ``/ip dhcp-server`` of ours is
        skipped: with no server of our own on that segment there is no
        baseline for calling a reply rogue, and an alert there would
        report our own legitimate neighbours.

        A config whose ``valid_servers`` is empty, or contains something
        that is not a MAC address, is refused **before the connection is
        opened** -- never filled in with a plausible guess. A wrong
        trusted-server list is not a partial guard; it is an alert on
        every legitimate lease, which is how a real one gets ignored.

        Idempotent: a second push of an unchanged set writes nothing.
        """
        desired = self._rogue_dhcp_alert_desired_rows(creds, alerts)
        await asyncio.to_thread(
            self._configure_rogue_dhcp_alerts_sync, creds, desired
        )

    @staticmethod
    def _rogue_dhcp_alert_desired_rows(
        creds: DeviceCredentials, alerts: Sequence[RogueDhcpAlertConfig]
    ) -> dict[str, dict[str, str]]:
        """Validate the whole request and render it into desired rows,
        before anything is connected to or written.

        Validated as a set rather than one at a time so a bad entry cannot
        leave half a fleet's worth of interfaces watched and the rest not
        -- the same "check before the first write" posture
        ``set_default_route_distances`` and ``configure_dhcp_pool`` take.
        """
        desired: dict[str, dict[str, str]] = {}
        for alert in alerts:
            interface = _safe_str(alert.interface)
            if interface is None:
                raise MikroTikDeviceError(
                    creds.host,
                    "configure_rogue_dhcp_alerts: an alert with no interface",
                )
            if interface in desired:
                raise MikroTikDeviceError(
                    creds.host,
                    "configure_rogue_dhcp_alerts: two alerts requested for "
                    f"interface {interface!r}; RouterOS holds one per "
                    "interface, so one would silently overwrite the other",
                )
            if not alert.valid_servers:
                raise MikroTikDeviceError(
                    creds.host,
                    f"configure_rogue_dhcp_alerts: interface {interface!r} has "
                    "no valid_servers; an alert that trusts nobody reports "
                    "every legitimate lease, and this adapter will not invent "
                    "a trusted server",
                )
            servers: list[str] = []
            for value in alert.valid_servers:
                mac = normalize_mac_address(value)
                if mac is None:
                    raise MikroTikDeviceError(
                        creds.host,
                        f"configure_rogue_dhcp_alerts: interface {interface!r} "
                        f"has valid_server {value!r}, which is not a MAC "
                        "address",
                    )
                servers.append(mac)
            row = {
                "interface": interface,
                "valid-server": ",".join(servers),
                "comment": _ROGUE_DHCP_ALERT_COMMENT,
            }
            timeout = _safe_str(alert.alert_timeout)
            if timeout is not None:
                # Omitted means "leave whatever the device has", never a
                # fabricated default -- ``_ensure_dhcp_server``'s reasoning
                # about ``lease_time``, unchanged.
                row["alert-timeout"] = timeout
            desired[interface] = row
        return desired

    def _configure_rogue_dhcp_alerts_sync(
        self, creds: DeviceCredentials, desired: dict[str, dict[str, str]]
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                serving = self._dhcp_serving_interfaces(api)
                menu = api.path("ip", "dhcp-server", "alert")
                rows = list(menu)
                for interface, fields in desired.items():
                    if interface not in serving:
                        logger.info(
                            "mikrotik_rogue_dhcp_alert_skipped_no_dhcp_server",
                            extra={"host": creds.host, "interface": interface},
                        )
                        continue
                    row = next(
                        (
                            candidate
                            for candidate in rows
                            if _safe_str(candidate.get("interface")) == interface
                        ),
                        None,
                    )
                    if row is None:
                        menu.add(**fields, disabled="no")
                        continue
                    changed = {
                        key: value
                        for key, value in fields.items()
                        if not self._same_rogue_dhcp_alert_field(
                            key, row.get(key), value
                        )
                    }
                    if _is_truthy(row.get("disabled")):
                        # Present and switched off: the state that looks
                        # guarded in the configuration and watches nothing.
                        changed["disabled"] = "no"
                    if changed:
                        menu.update(**{".id": row[".id"], **changed})
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_rogue_dhcp_alerts: {exc}"
                ) from exc
        finally:
            api.close()

    @staticmethod
    def _same_rogue_dhcp_alert_field(key: str, current: object, wanted: str) -> bool:
        """Whether the device's value for one alert field already means
        what we want it to -- per field, because two of the three do not
        survive a string comparison. See :func:`_same_valid_servers`."""
        if key == "valid-server":
            return _same_valid_servers(current, _split_valid_servers(wanted))
        if key == "alert-timeout":
            return _same_routeros_duration(current, wanted)
        return _safe_str(current) == wanted

    @staticmethod
    def _dhcp_serving_interfaces(api) -> set[str]:  # noqa: ANN001
        """The interfaces this router actually runs a DHCP server on.

        Disabled servers are excluded, through :func:`_is_truthy` rather
        than a string compare: a switched-off server hands out nothing, so
        an alert on that interface would have no offers of our own to
        compare an unknown one against.
        """
        serving: set[str] = set()
        for row in api.path("ip", "dhcp-server"):
            if _is_truthy(row.get("disabled")):
                continue
            interface = _safe_str(row.get("interface"))
            if interface is not None:
                serving.add(interface)
        return serving

    async def read_rogue_dhcp_alerts(
        self, creds: DeviceCredentials
    ) -> list[RogueDhcpAlertStatus]:
        """Whether this device is guarded against a rogue DHCP server,
        interface by interface. Reads only.

        Every interface serving DHCP appears in the answer, whether or not
        it has an alert row, because "hands out addresses, nothing watching
        it" is the finding worth having and it has no row of its own to be
        reported by. Every alert row appears too, including one on an
        interface that serves no DHCP -- reported rather than hidden, since
        it means the configuration and the device disagree.

        Presence and liveness are two separate fields
        (:class:`RogueDhcpAlertStatus`): RouterOS creates these rows
        disabled, so a check that looks only for presence certifies a
        router that is watching nothing.
        """
        return await asyncio.to_thread(self._read_rogue_dhcp_alerts_sync, creds)

    def _read_rogue_dhcp_alerts_sync(
        self, creds: DeviceCredentials
    ) -> list[RogueDhcpAlertStatus]:
        api = self._connect_api(creds)
        try:
            try:
                serving = self._dhcp_serving_interfaces(api)
                rows = list(api.path("ip", "dhcp-server", "alert"))
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"read_rogue_dhcp_alerts: {exc}"
                ) from exc
        finally:
            api.close()
        return _build_rogue_dhcp_alert_statuses(rows, serving)

    async def configure_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None:
        """Ported from
        ``network_config/renderers.py::render_port_forwarding_rule`` --
        same real ``/ip firewall nat add chain=dstnat ... action=dst-nat``
        operation, issued directly over the structured API.

        **The comment is the rule's identity**, exactly as it is for
        :meth:`configure_nat_masquerade`, and for the same reason. This was
        an unconditional ``.add()``, so the second push of an unchanged
        rule died on RouterOS's "already have such item" -- and re-pushing
        is an ordinary operation, not a recovery step. Keying instead on
        any RouterOS field would be worse than failing: ``dst-port``,
        ``to-addresses``, ``to-ports`` and ``protocol`` are precisely what
        a customer edits, so the push after an edit would match nothing,
        add a second rule, and leave the old one forwarding a live public
        port at a host that has moved. Keyed on the row's own id, the same
        push finds what it wrote last time and *updates* it.

        A ``"both"`` rule becomes two device rules, one per transport,
        under ``<id> tcp`` and ``<id> udp``. RouterOS cannot express "both"
        on a rule carrying a ``dst-port`` (see
        :func:`_port_forward_protocols`), and this domain both stores and
        defaults to that value, so refusing it would make the ordinary case
        unpushable. Narrowing a rule from both to one transport reaps the
        other's row rather than leaving it forwarding.

        ``disabled`` is normalized back to ``no`` via :func:`_is_truthy`,
        never by string comparison: a rule someone disabled by hand is
        forwarding nothing, and a re-push is the operator asking for it
        back.
        """
        await asyncio.to_thread(self._configure_port_forward_sync, creds, rule)

    def _configure_port_forward_sync(
        self, creds: DeviceCredentials, rule: PortForwardConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                self._ensure_port_forward_rules(api, rule)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_port_forward: {exc}"
                ) from exc
        finally:
            api.close()

    def _port_forward_desired(
        self, rule: PortForwardConfig, protocol: str
    ) -> dict[str, str]:
        """The complete state one device rule should be in.

        ``chain`` and ``action`` belong to the desired state, not only to
        the ``add``: a row found under this rule's comment but sitting on
        the wrong chain is this rule in a broken state, and correcting it
        is right where adding a second one alongside would not be.

        The two optional matchers are carried as ``""`` when unset rather
        than omitted, so that clearing a source restriction on the row
        really clears it on the device. Omitting them from the comparison
        would let a rule the operator narrowed to one source and then
        widened stay narrow, and the reverse -- a rule left restricted to a
        network that no longer exists -- forwards nothing while reporting
        success.
        """
        return {
            "chain": "dstnat",
            "action": "dst-nat",
            "protocol": protocol,
            "dst-port": str(rule.external_port),
            "to-addresses": rule.internal_ip,
            "to-ports": str(rule.internal_port),
            "dst-address": rule.dst_address or "",
            "src-address": rule.src_address or "",
        }

    def _ensure_port_forward_rules(self, api, rule: PortForwardConfig) -> None:
        """Brings this rule's whole set of device rows into line: update
        what is already there under its comment, add what is missing, drop
        what it no longer claims."""
        wanted = {
            _port_forward_comment(rule.rule_id, protocol): protocol
            for protocol in _port_forward_protocols(rule.protocol)
        }
        menu = api.path("ip", "firewall", "nat")
        # Materialized before any write: adds append to the same live menu,
        # and iterating it while writing would revisit rows this call made.
        rows = [
            row
            for row in menu
            if _owns_port_forward_comment(row.get("comment"), rule.rule_id)
        ]
        found: set[str] = set()
        for row in rows:
            comment = str(row.get("comment"))
            protocol = wanted.get(comment)
            if protocol is None:
                # This rule's own row for a transport it no longer matches
                # -- left in place it would keep forwarding the port.
                menu.remove(row[".id"])
                continue
            found.add(comment)
            desired = self._port_forward_desired(rule, protocol)
            changed = {
                key: value
                for key, value in desired.items()
                if str(row.get(key) or "") != value
            }
            # Boolean, never string -- see ``_is_truthy``. RouterOS accepts
            # "no" on write and answers reads with a real bool, so comparing
            # the raw value against "no" reports a difference on every push
            # and issues a pointless update forever.
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
        for comment, protocol in wanted.items():
            if comment in found:
                continue
            # Empty optional matchers are dropped here, not sent blank: an
            # ``add`` naming a field with no value is not the same request
            # as one that never named it.
            fields = {
                key: value
                for key, value in self._port_forward_desired(rule, protocol).items()
                if value != ""
            }
            menu.add(**fields, comment=comment, disabled="no")

    async def delete_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None:
        """Removes every device row this rule owns, by the same comment
        identity :meth:`configure_port_forward` writes them under.

        Only ``rule.rule_id`` is read. The current field values deliberately
        are not: a row left from an earlier external port or internal host
        is still this rule's row, and matching on what the row says *now* is
        exactly how one would be orphaned -- still forwarding a public port,
        with nothing in this platform left pointing at it.

        Idempotent: removing what is already absent is a no-op, so deleting
        a rule twice, or one whose push never landed, completes cleanly.
        """
        await asyncio.to_thread(self._delete_port_forward_sync, creds, rule)

    def _delete_port_forward_sync(
        self, creds: DeviceCredentials, rule: PortForwardConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                menu = api.path("ip", "firewall", "nat")
                for row in list(menu):
                    if _owns_port_forward_comment(row.get("comment"), rule.rule_id):
                        menu.remove(row[".id"])
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"delete_port_forward: {exc}"
                ) from exc
        finally:
            api.close()

    # ------------------------------------------------------------------
    # NAT / internet access
    # ------------------------------------------------------------------

    async def resolve_wan_interface(self, creds: DeviceCredentials) -> str:
        """The router's own WAN-facing interface, derived from its live
        state -- never a hardcoded ``"WAN"``/``"ether1"``.

        **The rule: the interface the currently-usable default route
        leaves by.** A default route is the router's own statement of
        where the internet is, and it is the only signal on the box that
        is true by construction rather than by convention. Interface
        *names* are pure convention: a fleet router may call its uplink
        ``ether1``, ``WAN``, ``pppoe-out1`` or ``sfp1``, and this platform
        stores that name nowhere.

        The default route itself is picked by the same two-tier rule every
        other WAN read here uses (:func:`_select_default_route_row`:
        dynamic first, then an *active*, non-disabled static one) -- so
        this agrees with ``get_wan_health`` and ``get_active_default
        _gateway`` by construction rather than by a second, drifting copy.

        From that one route, four ordered ways to name its interface, each
        checked against the real ``/interface`` list before it is
        accepted:

        1. the route row's own ``interface`` field, when RouterOS
           populates it -- the device saying it outright;
        2. its ``immediate-gw``/``gateway`` token's ``%``-suffix
           (``"192.168.1.1%ether1"``), RouterOS v7's own way of naming the
           egress interface of a gateway route;
        3. the ``/ip address`` whose subnet actually contains the
           gateway -- the gateway is by definition reachable on the
           interface holding an address in its subnet, so this is a
           derivation, not a heuristic. This is the tier that resolves the
           ordinary DHCP-WAN router (uplink ``192.168.1.100/24`` on
           ``ether1``, gateway ``192.168.1.1``);
        4. the ``/ip dhcp-client`` that negotiated that same gateway. Not
           redundant with tier 3: a client mid-renewal has withdrawn its
           dynamic ``/ip address`` row while the default route still
           stands, which is precisely when a DHCP-WAN router would
           otherwise resolve to nothing.

        Note what is *not* used: bridge membership, name matching, "the
        first ethernet port", or the single interface holding an address.
        Each would return an answer on a router where the honest answer is
        "cannot tell".

        Raises :class:`MikroTikWanInterfaceError` when no tier produces a
        real interface -- the router has no usable default route at all
        (a genuine outage, or an uplink RouterOS has stopped considering
        active), or its gateway sits on nothing this router knows about.
        Guessing here is worse than failing: the wrong ``out-interface``
        either masquerades guest traffic onto an internal segment or
        matches nothing, and both report success.
        """
        return await asyncio.to_thread(self._resolve_wan_interface_sync, creds)

    def _resolve_wan_interface_sync(self, creds: DeviceCredentials) -> str:
        api = self._connect_api(creds)
        try:
            return self._resolve_wan_interface(api, creds)
        finally:
            api.close()

    def _resolve_wan_interface(self, api, creds: DeviceCredentials) -> str:
        """Same resolution as :meth:`resolve_wan_interface`, against an
        already-open connection -- so a NAT push resolves the WAN and
        writes the rule over one connection rather than two."""
        try:
            route_rows = list(api.path("ip", "route"))
            address_rows = list(api.path("ip", "address"))
            interface_rows = list(api.path("interface"))
        except LibRouterosError as exc:
            raise MikroTikDeviceError(
                creds.host, f"resolve_wan_interface: {exc}"
            ) from exc
        try:
            dhcp_client_rows = list(api.path("ip", "dhcp-client"))
        except LibRouterosError:
            # Tier 4 only. An unreadable optional menu must not sink a
            # resolution the earlier tiers can already make on their own.
            dhcp_client_rows = []

        interface_names = {
            str(row["name"]) for row in interface_rows if row.get("name")
        }
        resolved = _select_wan_interface(
            route_rows, address_rows, dhcp_client_rows, interface_names
        )
        if resolved is None:
            raise MikroTikWanInterfaceError(
                creds.host,
                "could not determine the WAN interface: no usable default "
                "route, or its gateway is on no known interface",
            )
        return resolved

    async def configure_nat_masquerade(
        self, creds: DeviceCredentials, *, rule: NatRuleConfig
    ) -> None:
        """Realizes ``/ip firewall nat add chain=srcnat
        src-address=<subnet> out-interface=<wan> action=masquerade
        comment="WyfyGuest VLAN <id>"`` -- the rule that turns a routed
        but isolated VLAN into one whose guests actually reach the
        internet.

        Nothing in it is hardcoded. The subnet is the VLAN's own
        ``src_address``; the interface is resolved from the router's live
        default route (:meth:`resolve_wan_interface`) unless the caller
        passed an explicit override; the comment carries the VLAN's real
        id.

        **The comment is the rule's identity, and that is the whole
        design.** Every other field is something an operator edits:
        re-subnet a VLAN and ``src-address`` changes, re-cable a site and
        ``out-interface`` changes. Keyed on any of those, the next push
        would find no match, add a second rule, and leave the first one
        masquerading a subnet nothing uses -- silent, cumulative, and
        invisible in this platform's own UI. Keyed on the comment, the
        same push finds the rule it wrote last time and *updates* it,
        which is what "if the VLAN config changes, update the existing
        rule" actually requires.

        ``disabled`` is normalized back to ``no`` via :func:`_is_truthy`,
        never by string comparison: a rule someone disabled by hand is not
        providing internet access, and a re-push is the operator asking
        for it.
        """
        await asyncio.to_thread(self._configure_nat_masquerade_sync, creds, rule)

    def _configure_nat_masquerade_sync(
        self, creds: DeviceCredentials, rule: NatRuleConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            # The WAN is resolved before anything is written: a rule whose
            # out-interface could not be determined must not exist at all,
            # half-written and matching everything.
            out_interface = self._nat_out_interface(api, creds, rule)
            try:
                self._ensure_nat_masquerade_rule(api, rule, out_interface)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_nat_masquerade: {exc}"
                ) from exc
        finally:
            api.close()

    def _nat_out_interface(
        self, api, creds: DeviceCredentials, rule: NatRuleConfig
    ) -> str:
        """The interface to masquerade out of -- resolved from the router
        unless the caller named one, and in either case confirmed to be a
        real interface on this device first.

        The check is not redundant for the override path: RouterOS does
        reject an unknown interface name on a firewall rule, but with a
        message about an input not matching a value, attributed to the NAT
        write. Checking first names the missing interface instead.
        """
        if rule.out_interface is None:
            return self._resolve_wan_interface(api, creds)
        try:
            names = {
                str(row["name"])
                for row in api.path("interface")
                if row.get("name")
            }
        except LibRouterosError as exc:
            raise MikroTikDeviceError(
                creds.host, f"configure_nat_masquerade: {exc}"
            ) from exc
        if rule.out_interface not in names:
            raise MikroTikWanInterfaceError(
                creds.host,
                f"no interface named '{rule.out_interface}' exists on this device",
            )
        return rule.out_interface

    def _ensure_nat_masquerade_rule(
        self, api, rule: NatRuleConfig, out_interface: str
    ) -> None:
        """Creates this VLAN's masquerade rule, or brings the one already
        carrying its comment into line with what is wanted now.

        ``chain`` and ``action`` are part of the desired state, not just of
        the ``add``: a rule found by this VLAN's comment but sitting on the
        wrong chain is this VLAN's rule in a broken state, and correcting
        it is right where adding a second one alongside it would not be.
        """
        comment = _nat_rule_comment(rule.vlan_id)
        desired = {
            "chain": "srcnat",
            "action": "masquerade",
            "src-address": rule.src_address,
            "out-interface": out_interface,
        }
        menu = api.path("ip", "firewall", "nat")
        for row in menu:
            if row.get("comment") != comment:
                continue
            changed = {
                key: value for key, value in desired.items() if row.get(key) != value
            }
            # Boolean, never string -- see ``_is_truthy``. Comparing the raw
            # value against "no" reports a difference on every single push
            # and issues a pointless update forever.
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return
        menu.add(**desired, comment=comment, disabled="no")

    async def delete_nat_masquerade(
        self, creds: DeviceCredentials, *, rule: NatRuleConfig
    ) -> None:
        """Removes this VLAN's masquerade rule, by the same comment
        identity :meth:`configure_nat_masquerade` writes it under.

        Only ``rule.vlan_id`` is read. ``src_address`` deliberately is not:
        a rule left from an older subnet is still this VLAN's rule, and
        matching on the current subnet is exactly how it would be orphaned
        instead of removed.

        **No WAN resolution happens here**, unlike on the write path. A
        VLAN must stay removable from a router whose uplink is down --
        which is the state a router is often in when someone is tearing
        its configuration down -- and the comment is enough to find the
        rule without knowing where the internet is.

        Idempotent: removing what is already absent is a no-op, not an
        error.
        """
        await asyncio.to_thread(self._delete_nat_masquerade_sync, creds, rule)

    def _delete_nat_masquerade_sync(
        self, creds: DeviceCredentials, rule: NatRuleConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                self._remove_where(
                    api,
                    ("ip", "firewall", "nat"),
                    "comment",
                    _nat_rule_comment(rule.vlan_id),
                )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"delete_nat_masquerade: {exc}"
                ) from exc
        finally:
            api.close()

    # ------------------------------------------------------------------
    # WAN failover
    # ------------------------------------------------------------------

    async def read_default_routes(self, creds: DeviceCredentials) -> list[DefaultRoute]:
        """Every ``0.0.0.0/0`` route in the device's own ``main`` table,
        each resolved to the interface it actually leaves by.

        The read a failover is decided from, and the reason this is a
        separate call rather than something folded into the write: a
        caller has to be able to refuse -- because the target is not
        active, because the platform and the router disagree about the
        topology, because the route is one RouterOS will not let anyone
        modify -- *before* it has moved anything. Nothing here is
        filtered: inactive, disabled and dynamic rows are all returned,
        flagged, because each is a different refusal.
        """
        return await asyncio.to_thread(self._read_default_routes_sync, creds)

    def _read_default_routes_sync(self, creds: DeviceCredentials) -> list[DefaultRoute]:
        api = self._connect_api(creds)
        try:
            return self._read_default_routes(api, creds)
        finally:
            api.close()

    def _read_default_routes(self, api, creds: DeviceCredentials) -> list[DefaultRoute]:
        """Same read, against an already-open connection -- so the write
        below re-reads and validates over the connection it then writes on
        rather than trusting what a previous connection saw."""
        try:
            route_rows = list(api.path("ip", "route"))
            address_rows = list(api.path("ip", "address"))
            interface_rows = list(api.path("interface"))
        except LibRouterosError as exc:
            raise MikroTikDeviceError(
                creds.host, f"read_default_routes: {exc}"
            ) from exc
        try:
            dhcp_client_rows = list(api.path("ip", "dhcp-client"))
        except LibRouterosError:
            # Tier 4 of interface resolution only. An unreadable optional
            # menu must not sink a read the earlier tiers can satisfy.
            dhcp_client_rows = []
        interface_names = {
            str(row["name"]) for row in interface_rows if row.get("name")
        }
        return _build_default_routes(
            route_rows, address_rows, dhcp_client_rows, interface_names
        )

    async def set_default_route_distances(
        self, creds: DeviceCredentials, *, distances: Mapping[str, int]
    ) -> None:
        """Set the administrative distance of the ``main``-table default
        route leaving by each named interface. **This is what failover
        means on a RouterOS device in this platform.**

        WHY DISTANCE, AND NOT THE ALTERNATIVES:

        * *Disabling the primary's route* moves traffic too, and moves it
          just as fast. It is rejected because it takes the primary out of
          RouterOS's own decision entirely: while it is disabled the
          router cannot fall back to it no matter what happens to the
          backup, so a backup that dies during a failover leaves the site
          dark even though a working uplink is sitting right there. With
          distances, both routes keep their ``check-gateway=ping`` and
          RouterOS keeps doing what it is good at -- the platform only
          says which it should prefer. It also fails a blunter test: if
          this backend never gets to run the reversal (process killed,
          credentials rotated, site unreachable), a wrong distance is a
          preference nobody notices, and an administratively disabled
          route is an uplink nothing will ever bring back.
        * *``check-gateway``* is not an alternative at all -- it is the
          automatic mechanism, already provisioned on every route this
          platform writes (``render_wan_routing_section``). There is no
          way to tell RouterOS "pretend this gateway is down", so it
          cannot express an operator's deliberate failover.
        * *``/routing rule`` or policy routing* would work, and would
          collide head-on with the routing-marks and ``to_wan<N>`` tables
          ``render_wan_mangle_section`` already writes for load balancing.
          Two mechanisms deciding the same thing is how a site ends up
          with traffic that follows neither.

        WHAT ACTUALLY HAPPENS TO TRAFFIC. RouterOS recomputes the FIB when
        a distance changes, so new connections take the new uplink
        immediately. Established connections do NOT survive: they were
        masqueraded to the old uplink's source address, and the far end
        will not accept them from a different one. A failover is a brief,
        real interruption for anyone mid-download; it is not, and cannot
        be made, seamless on this hardware.

        ON PRIMARY RECOVERY: **sticky**. Distances are exactly what this
        method set them to, so a primary coming back does not take traffic
        back on its own -- it is reclaimed only by an explicit failback
        (which the caller may automate via ``IspLink.auto_failback``, but
        that is the platform deciding, not the router flapping). The one
        thing the router still does by itself is the safety net that
        disabling would have removed: if the *backup* then fails,
        ``check-gateway`` deactivates its route and the primary's route --
        still present, still probed, merely at a worse distance -- takes
        over.

        VALIDATED IN FULL BEFORE THE FIRST WRITE. A half-applied swap can
        leave two default routes tied at the lowest distance, which is
        RouterOS load sharing across an uplink that is down -- strictly
        worse than the state it started from. Every route is resolved and
        checked before any of them is written, so no *validation* failure
        can produce that state.

        WHAT VALIDATION DOES NOT CLOSE. RouterOS has no multi-row atomic
        update, so a device error raised partway through the write loop
        still leaves the earlier routes changed and the later ones not --
        the tie above, reachable and not preventable here. Two things
        follow, and both are deliberate. The failure is raised, never
        swallowed, so the caller records ``failed`` rather than a green
        badge. And the error names the routes that were already written,
        because an operator looking at a failed failover needs to know
        whether the device is in the state it started in or halfway to the
        new one -- reading it back off the router is the only alternative,
        and that is exactly what an outage leaves no time for.

        IDEMPOTENT ON REAL VALUES. A route already carrying the requested
        distance is skipped, so re-triggering an already-applied failover
        issues no write at all. The comparison is on parsed integers, not
        on RouterOS's reply strings.
        """
        await asyncio.to_thread(
            self._set_default_route_distances_sync, creds, dict(distances)
        )

    def _set_default_route_distances_sync(
        self, creds: DeviceCredentials, distances: dict[str, int]
    ) -> None:
        api = self._connect_api(creds)
        try:
            routes = self._read_default_routes(api, creds)
            by_interface: dict[str, list[DefaultRoute]] = {}
            for route in routes:
                if route.interface is None:
                    continue
                by_interface.setdefault(route.interface, []).append(route)

            pending: list[tuple[DefaultRoute, int]] = []
            for interface, desired in distances.items():
                matches = by_interface.get(interface, [])
                if not matches:
                    raise MikroTikRouteNotFoundError(
                        creds.host,
                        f"no main-table default route leaves by interface "
                        f"'{interface}' on this device",
                    )
                if len(matches) > 1:
                    raise MikroTikAmbiguousRouteError(
                        creds.host,
                        f"{len(matches)} main-table default routes leave by "
                        f"interface '{interface}'; which one is this uplink's "
                        f"has no single answer",
                    )
                route = matches[0]
                if route.distance == desired:
                    continue
                if route.dynamic:
                    raise MikroTikImmutableRouteError(
                        creds.host,
                        f"the default route on '{interface}' is dynamic "
                        f"(RouterOS created it, and refuses /ip route set on "
                        f"it), so its distance cannot be changed",
                    )
                pending.append((route, desired))

            if not pending:
                return
            menu = api.path("ip", "route")
            applied: list[str] = []
            for route, desired in pending:
                try:
                    menu.update(**{".id": route.route_id, "distance": str(desired)})
                except LibRouterosError as exc:
                    # Name what already landed -- see this method's own
                    # "WHAT VALIDATION DOES NOT CLOSE" note. Without this
                    # the operator cannot tell a no-op failure from a
                    # half-applied swap without reading the router back.
                    done = (
                        "; already applied: " + ", ".join(applied)
                        if applied
                        else "; no route was changed"
                    )
                    raise MikroTikDeviceError(
                        creds.host,
                        f"set_default_route_distances: {exc}{done}",
                    ) from exc
                applied.append(f"{route.interface}->distance {desired}")
        finally:
            api.close()

    async def ensure_wan_egress(
        self, creds: DeviceCredentials, *, interface: str
    ) -> None:
        """Make sure traffic leaving by ``interface`` is masqueraded and
        that the interface is in the ``WAN`` interface list.

        **THE NAT PROBLEM THIS EXISTS FOR.** A router provisioned by this
        platform carries ``/ip firewall nat`` ``chain=srcnat
        action=masquerade out-interface=ether1
        comment="cloudguest-nat-wan1"`` -- hard-bound to the primary port.
        Move the default route to a backup and that rule stops matching:
        guest traffic leaves the router from an un-NATed RFC1918 source
        address and dies at the first upstream hop. Every guest loses
        internet *because of* the failover, and the route move looks
        perfectly correct on the device.

        **ADDITIVE, NEVER A REWRITE, AND THAT IS THE WHOLE POINT.** The
        obvious fix is to widen the existing rule to
        ``out-interface-list=WAN``. It is rejected for two reasons. First,
        it is a mutation of a live router-wide NAT rule -- the exact class
        of change that took a guest network down on 2026-08-18 -- carried
        out at the moment a site is already in an outage, which is the
        worst possible time to be wrong. Second, it is genuinely wider
        than intended: this platform's *own* provisioning script adds
        discovered uplinks to the ``WAN`` list at runtime
        (``DISCOVERED_WAN_LIST_COMMENT``), so a list-scoped masquerade
        starts NATing out of whatever lands in that list later, including
        interfaces nobody decided should carry guest traffic.

        What this does instead is what the provisioning script already
        does per WAN slot: ensure the target interface has *its own*
        masquerade rule. A masquerade rule matches only traffic that
        actually leaves its own ``out-interface``, so adding the backup's
        rule changes nothing whatsoever about traffic on the primary --
        it is inert until the route moves, and stays inert after a
        failback. No existing rule is read for permission, edited, or
        removed.

        **The existence check is on effect, not on identity.** Any
        enabled, un-narrowed ``srcnat``/``masquerade`` rule on this
        interface already answers the question "is traffic leaving here
        NATed?" -- whoever wrote it. So a router provisioned with
        ``cloudguest-nat-wan2`` gets nothing added, rather than a second,
        redundant rule accumulating on every failover. A rule carrying a
        ``src-address``, an ``in-interface`` or a port narrows to less
        than all guest traffic (one VLAN's own rule looks exactly like
        this) and is deliberately not counted.

        **WAN list membership too**, for the same "otherwise the route
        moves and traffic still does not flow" reason: the firewall this
        platform provisions matches ``in-interface-list=WAN``, and an
        uplink outside that list is one the input/forward rules treat as
        an internal segment.

        Idempotent in both halves, and the whole thing is a no-op on a
        router already configured for this uplink.
        """
        await asyncio.to_thread(self._ensure_wan_egress_sync, creds, interface)

    def _ensure_wan_egress_sync(
        self, creds: DeviceCredentials, interface: str
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                names = {
                    str(row["name"])
                    for row in api.path("interface")
                    if row.get("name")
                }
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"ensure_wan_egress: {exc}"
                ) from exc
            if interface not in names:
                # Named first, rather than left to RouterOS to reject with
                # a message about an input not matching a value attributed
                # to whichever write happened to go first.
                raise MikroTikWanInterfaceError(
                    creds.host,
                    f"no interface named '{interface}' exists on this device",
                )
            try:
                self._ensure_wan_list_member(api, interface)
                self._ensure_uplink_masquerade(api, interface)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"ensure_wan_egress: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_wan_list_member(self, api, interface: str) -> None:
        """``/interface list member`` for ``list=WAN``, added only if this
        interface is not already a member under any comment."""
        menu = api.path("interface", "list", "member")
        for row in menu:
            if row.get("interface") == interface and row.get("list") == "WAN":
                if _is_truthy(row.get("disabled")):
                    # Membership that exists but is switched off is not
                    # membership. Boolean, never a string comparison --
                    # see ``_is_truthy``.
                    menu.update(**{".id": row[".id"], "disabled": "no"})
                return
        menu.add(
            list="WAN",
            interface=interface,
            comment=_uplink_wan_list_comment(interface),
            disabled="no",
        )

    def _ensure_uplink_masquerade(self, api, interface: str) -> None:
        """A blanket ``srcnat``/``masquerade`` on this interface, added
        only if nothing already provides one -- see
        :meth:`ensure_wan_egress` for why the check is on effect rather
        than on this method's own comment."""
        menu = api.path("ip", "firewall", "nat")
        own_comment = _uplink_nat_comment(interface)
        for row in menu:
            if (
                row.get("chain") != "srcnat"
                or row.get("action") != "masquerade"
                or row.get("out-interface") != interface
            ):
                continue
            if any(row.get(field) for field in _NAT_NARROWING_FIELDS):
                continue
            if _is_truthy(row.get("disabled")):
                if row.get("comment") == own_comment:
                    # Ours, switched off. Re-enabling something this
                    # method wrote is repairing its own state.
                    menu.update(**{".id": row[".id"], "disabled": "no"})
                    return
                # Someone else's rule, deliberately disabled. Not
                # re-enabled -- that is a decision about their rule --
                # and not counted as covering, so a rule of our own is
                # added alongside it.
                continue
            return
        menu.add(
            chain="srcnat",
            action="masquerade",
            **{"out-interface": interface},
            comment=own_comment,
            disabled="no",
        )

    async def set_radius_client_config(
        self, creds: DeviceCredentials, *, config: RadiusClientConfig
    ) -> None:
        """Ported from
        ``network_config/renderers.py::render_radius_client`` -- the same
        ``/radius add`` (registers this router as a RADIUS/hotspot NAS
        client) and unconditional ``/radius incoming set accept=yes
        port=3799`` (RFC 5176 Change-of-Authorization enablement, a
        router-global setting, not per-client) operations, issued directly
        over the structured API. See module docstring for why
        ``src-address`` is carried here, unlike in an earlier version of
        this port that dropped it as tunnel-specific: the hub's FreeRADIUS
        matches a request to a ``client{}`` stanza by source address, so a
        ``/radius`` row without it registers a client that cannot
        authenticate. See :class:`RadiusClientConfig`.

        ## This converges; it used to append

        The previous implementation issued a bare ``/radius add`` every
        time, with no read first. Two pushes meant two ``/radius`` rows for
        the same server -- and two NAS registrations with possibly
        different secrets is a router that authenticates intermittently
        depending on which row RouterOS consults. The script half
        (``render_radius_client``) still has that shape; this one no longer
        does.

        **Identity is the natural key, not the comment.** Everywhere else
        in this adapter the comment is the handle, because every other
        field is something a customer edits. Here the row is identified by
        ``service=hotspot`` plus ``address=<radius server>``, because that
        pair *is* the identity as far as RouterOS is concerned -- one NAS
        registration per server -- and because the row already on the lab
        router carries ``comment=cloudguest-radius``, a marker this
        codebase has never written. Somebody set it by hand at
        provisioning. Keying on our own comment would not find it, and we
        would add a second row beside a working one. So an existing row for
        this server is **adopted**: updated in place and stamped with this
        platform's comment, which makes it ours from then on.

        ## The CoA half

        ``/ip radius incoming`` is router-global, not per-client, and is
        converged the same way: read, compare, write only on a difference.
        ``accept`` is resolved through :func:`_is_truthy` rather than a
        string compare, for the reason documented on
        :meth:`_ensure_dhcp_server` -- the API answers a read with a real
        ``bool`` while accepting ``"yes"``/``"no"`` on write.

        Idempotent throughout: re-pushing an unchanged registration issues
        no write at all."""
        await asyncio.to_thread(self._set_radius_client_config_sync, creds, config)

    def _set_radius_client_config_sync(
        self, creds: DeviceCredentials, config: RadiusClientConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                self._ensure_radius_client_row(api, config)
                self._ensure_radius_incoming(api, config)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"set_radius_client_config: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_radius_client_row(self, api, config: RadiusClientConfig) -> None:  # noqa: ANN001
        """The ``/radius`` NAS registration, one per server -- see
        :meth:`set_radius_client_config` for why the natural key and not
        the comment."""
        desired = {
            "service": "hotspot",
            "address": config.radius_server_host,
            "secret": config.radius_secret,
            "authentication-port": str(config.auth_port),
            "accounting-port": str(config.acct_port),
            "comment": _RADIUS_CLIENT_COMMENT,
        }
        if config.src_address:
            desired["src-address"] = config.src_address

        menu = api.path("radius")
        for row in list(menu):
            same_server = (
                str(row.get("service", "")) == "hotspot"
                and str(row.get("address", "")) == config.radius_server_host
            )
            if not same_server:
                continue
            changed = {
                key: value
                for key, value in desired.items()
                if str(row.get(key, "")) != value
            }
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return
        menu.add(**desired, disabled="no")

    def _ensure_radius_incoming(self, api, config: RadiusClientConfig) -> None:  # noqa: ANN001
        """RFC 5176 Change-of-Authorization enablement.

        Router-global: RouterOS has exactly one ``/radius incoming``
        settings object, so this is written once regardless of how many
        client rows exist, and re-writing it per push is a no-op rather
        than a duplicate.
        """
        wanted_port = str(config.coa_port)
        for row in api.path("radius", "incoming"):
            if _is_truthy(row.get("accept")) and str(row.get("port", "")) == wanted_port:
                return
            break
        api.path("radius", "incoming").update(accept="yes", port=wanted_port)

    async def configure_content_filter_rule(
        self, creds: DeviceCredentials, *, rule: ContentFilterRuleConfig
    ) -> None:
        """Ported from
        ``network_config/renderers.py::render_content_filter_rule``/
        ``render_content_filter_enforcement`` -- the same real RouterOS
        objects, issued directly over the structured API instead of as
        script text. See that module's own "Content Filtering" docstring
        section for the full write-up this ports; summarized here for
        this file's own "honest scope" convention:

        ## Honest scope: DNS sinkhole + address-list/firewall-filter only

        ``rule.value_type == "domain"`` issues two real
        ``/ip dns static add`` commands -- an exact-name match and a
        ``regexp=`` match for every subdomain (RouterOS treats ``name=``
        and ``regexp=`` as mutually exclusive per entry, so one entry
        cannot cover both) -- each pointing at
        :data:`_CONTENT_FILTER_SINKHOLE_ADDRESS` (this platform's own
        loopback, ``127.0.0.1``: always exists, needs no LAN host
        actually listening on it, never ARPs a real device). This makes a
        blocked domain simply fail to resolve for a guest device using
        this router as its DNS server -- the honest, low-overhead
        mechanism this platform's own low-power test hardware (a
        MikroTik hEX lite, documented elsewhere in this codebase) can
        afford, unlike Layer7 regex matching against every packet's
        payload.

        ``rule.value_type == "ip_cidr"`` issues one real
        ``/ip firewall address-list add`` command adding ``rule.value``
        to :data:`_CONTENT_FILTER_ADDRESS_LIST_NAME`, then calls
        :meth:`_ensure_content_filter_enforcement_rule` -- a real,
        read-before-write check for an existing ``/ip firewall filter``
        DROP rule already matching that whole address-list by its own
        fixed comment, adding it only if genuinely absent. This avoids
        genuinely duplicating that DROP rule on the device every time a
        second, third, ... IP/CIDR rule is configured (the DROP rule
        matches list *membership*, not any one specific address, so it is
        only ever needed once per router) -- a real correctness
        requirement, not a cosmetic one: a populated address-list with no
        DROP rule referencing it is exactly the "looks wired up but
        isn't" gap this codebase's own
        ``app.domains.mac_authorization`` module docstring already called
        out and fixed for its own whitelist entries before this addition
        existed.

        ## What this deliberately does not do

        No Layer7 protocol matching, no ``/ip proxy`` web-proxy, and --
        under no circumstances -- TLS interception (HTTPS MITM) to
        inspect or block encrypted traffic by content. See
        ``app.domains.content_filtering``'s own module docstring
        (cloud-guest-repo) for the full customer-facing scope write-up
        this ports; that same reasoning applies here unchanged.

        ## The comment is the rule's identity, and that is the whole design

        Every object above carries
        ``"WyfyGuest content filter <rule_id>[ (subdomains)]: <label>"``,
        and each write finds its object again by the marker in front of
        the colon. Nothing else on the row can serve: ``name``/``regexp``/
        ``address`` *are* the blocked target, and ``label`` is the name
        the customer typed, so both change the moment somebody edits the
        rule. Keyed on either, the next push would match nothing, add a
        second sinkhole, and leave the first one still blocking a site the
        customer already unblocked -- silent, cumulative, and invisible in
        this platform's own UI. Keyed on the marker, the same push finds
        what it wrote last time and *updates* it. This is
        :meth:`configure_nat_masquerade`'s reasoning applied to a domain
        with two objects per rule instead of one.

        A rule that changed ``value_type`` since its last push is the one
        case where the objects to write are not the objects already there,
        so the mechanism it is no longer using is torn down first -- a
        domain rule re-typed to ``ip_cidr`` would otherwise leave its DNS
        sinkhole answering forever, with this push reporting success.

        ``disabled`` is normalized back to ``no`` through
        :func:`_is_truthy`, never by string comparison: an entry somebody
        disabled by hand is blocking nothing, a re-push is the customer
        asking for it again, and comparing the raw value against ``"no"``
        would instead issue a pointless update on every single push.

        Idempotent throughout: re-pushing an unchanged rule adds nothing
        and raises nothing. RouterOS answers a duplicate ``add`` with
        "already have such item", and re-pushing is an ordinary operation
        -- the customer pressing the button twice, or a retry after a
        partial failure."""
        await asyncio.to_thread(self._configure_content_filter_rule_sync, creds, rule)

    def _configure_content_filter_rule_sync(
        self, creds: DeviceCredentials, rule: ContentFilterRuleConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                if rule.value_type == "ip_cidr":
                    # A rule re-typed from "domain" leaves two DNS entries
                    # still answering for a name nobody is blocking any
                    # more; the objects this rule no longer uses come off
                    # before the ones it does go on.
                    self._remove_content_filter_dns_entries(api, rule.rule_id)
                    self._ensure_content_filter_address_list_entry(api, rule)
                    self._ensure_content_filter_enforcement_rule(api)
                else:
                    self._remove_where_prefixed(
                        api,
                        ("ip", "firewall", "address-list"),
                        "comment",
                        _content_filter_marker(rule.rule_id),
                    )
                    self._ensure_content_filter_dns_entries(api, rule)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_content_filter_rule: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_content_filter_address_list_entry(
        self, api, rule: ContentFilterRuleConfig
    ) -> None:
        """Puts this rule's IP/CIDR in the shared blocked address-list, or
        corrects the entry already carrying this rule's marker.

        ``address`` is part of the desired state, not only of the ``add``:
        an entry found by this rule's marker but holding a different
        address is this rule blocking the wrong destination, and correcting
        it is right where adding a second entry beside it would not be.
        """
        self._ensure_content_filter_object(
            api,
            ("ip", "firewall", "address-list"),
            marker=_content_filter_marker(rule.rule_id),
            desired={
                "list": _CONTENT_FILTER_ADDRESS_LIST_NAME,
                "address": rule.value,
                "comment": _content_filter_comment(rule.rule_id, rule.label),
            },
        )

    def _ensure_content_filter_dns_entries(
        self, api, rule: ContentFilterRuleConfig
    ) -> None:
        """The two ``/ip dns static`` entries one blocked domain becomes.

        Two, not one, because RouterOS treats ``name=`` and ``regexp=`` as
        mutually exclusive per entry: the first sinkholes the domain
        itself, the second every subdomain of it. They carry different
        markers so a later push can find and correct each on its own --
        one marker for both would make the second write update the first
        entry and the domain's subdomains stop being blocked at all.
        """
        domain = rule.value
        self._ensure_content_filter_object(
            api,
            ("ip", "dns", "static"),
            marker=_content_filter_marker(rule.rule_id),
            desired={
                "name": domain,
                "type": "A",
                "address": _CONTENT_FILTER_SINKHOLE_ADDRESS,
                "comment": _content_filter_comment(rule.rule_id, rule.label),
            },
        )
        self._ensure_content_filter_object(
            api,
            ("ip", "dns", "static"),
            marker=_content_filter_marker(rule.rule_id, subdomains=True),
            desired={
                "regexp": _domain_subdomain_regex(domain),
                "type": "A",
                "address": _CONTENT_FILTER_SINKHOLE_ADDRESS,
                "comment": _content_filter_comment(
                    rule.rule_id, rule.label, subdomains=True
                ),
            },
        )

    def _ensure_content_filter_object(
        self,
        api,
        path_segments: tuple[str, ...],
        *,
        marker: str,
        desired: dict[str, str],
    ) -> None:
        """Creates one content-filtering object, or brings the one already
        carrying ``marker`` into line with ``desired``.

        The row is found by the marker *prefix* of its comment rather than
        by the whole comment, because the customer's label lives in the
        same field behind it -- see :func:`_content_filter_comment`. A
        renamed rule therefore updates its comment in place instead of
        being missed and duplicated.

        ``disabled`` is compared as a boolean through :func:`_is_truthy`,
        never as a string: RouterOS accepts ``"no"`` on write and answers
        reads with a real ``bool``, so a string comparison reports a
        difference on every single push and issues a pointless update
        forever.
        """
        menu = api.path(*path_segments)
        for row in menu:
            if not str(row.get("comment", "")).startswith(marker):
                continue
            changed = {
                key: value for key, value in desired.items() if row.get(key) != value
            }
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return
        menu.add(**desired, disabled="no")

    def _remove_content_filter_dns_entries(self, api, rule_id: str) -> None:
        """Both of one rule's DNS entries, by their own two markers."""
        for subdomains in (False, True):
            self._remove_where_prefixed(
                api,
                ("ip", "dns", "static"),
                "comment",
                _content_filter_marker(rule_id, subdomains=subdomains),
            )

    async def delete_content_filter_rule(
        self, creds: DeviceCredentials, *, rule: ContentFilterRuleConfig
    ) -> None:
        """Removes the objects :meth:`configure_content_filter_rule`
        created, by the same marker identity it writes them under.

        Only ``rule.rule_id`` is read. ``value`` and ``value_type``
        deliberately are not: an entry left from a domain the customer has
        since edited -- or from before they switched the rule from a
        domain to an address -- is still *this rule's* entry, and matching
        on the current value is exactly how it would be orphaned instead of
        removed. Both mechanisms are swept for the same reason.

        **The shared ``/ip firewall filter`` DROP rule is deliberately left
        in place.** It is router-global, referencing the address-list by
        name rather than any one entry, and every other ``ip_cidr`` rule on
        this router depends on it -- removing it here would silently
        unblock all of them. Once this rule's own membership is gone the
        DROP rule simply matches one fewer address, and against an empty
        list it drops nothing at all. It is created once, by
        :meth:`_ensure_content_filter_enforcement_rule`, and belongs to the
        router rather than to any rule that made it necessary.

        Idempotent: removing what is already absent is a no-op, not an
        error, so a retry after a partial failure completes cleanly.
        """
        await asyncio.to_thread(self._delete_content_filter_rule_sync, creds, rule)

    def _delete_content_filter_rule_sync(
        self, creds: DeviceCredentials, rule: ContentFilterRuleConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                # The address-list entry goes before the DNS ones for the
                # only ordering that matters here: it is the object the
                # surviving DROP rule's match depends on, so it stops being
                # dropped first and nothing is ever half-enforced against a
                # list this rule has already left.
                self._remove_where_prefixed(
                    api,
                    ("ip", "firewall", "address-list"),
                    "comment",
                    _content_filter_marker(rule.rule_id),
                )
                self._remove_content_filter_dns_entries(api, rule.rule_id)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"delete_content_filter_rule: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_content_filter_enforcement_rule(self, api) -> None:  # noqa: ANN001
        """Real read-before-write convergence for the one, router-global
        ``/ip firewall filter`` DROP rule every ``ip_cidr``-type content
        filter rule relies on -- see
        ``configure_content_filter_rule``'s own docstring for why this
        must exist exactly once, not once per rule.

        ## Position is managed, not left to where RouterOS appends

        This used to ``add`` with no ``place-before``, so the DROP landed
        at the bottom of ``forward``, and the dedup check read only the
        comment -- once the rule existed, nothing ever verified or
        corrected where it sat. Any ``accept`` ahead of it silently ended
        blocking.

        It is now placed immediately **before the first ``accept`` in
        ``forward``**, and the position is re-checked on every push rather
        than only at creation.

        Two device tests on RouterOS 7.23.3 (hEX lite) make that placement
        buildable rather than guessed, and both are recorded in
        ``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md`` §7:

        * **T1** -- ``librouteros``' ``Path.add()`` accepts ``place-before``
          and it takes a ``.id``, not an ordinal. Verified: rules added
          ``a``, ``b``, then ``c`` with ``place-before=<b .id>`` printed in
          the order ``a, c, b``.
        * **T2** -- a static rule *can* sit above hotspot's dynamic
          ``forward`` rules. Verified: a rule placed before the first
          dynamic row landed at index 0, above both ``jump`` rules.

        ## Why the first accept, and why that is safe here

        Read off the lab router, ``forward`` is two dynamic hotspot
        ``jump`` rules (both gated ``hotspot=...,!auth``, so authenticated
        guest traffic does not match them and falls through), three
        ``cloudguest-block-*`` drops, then
        ``accept cloudguest-fw-fwd-established``
        (``connection-state=established,related``) and a drop for
        ``invalid``.

        Below that accept, a blocked destination is only dropped on a *new*
        connection: a flow already established when the block was added
        keeps flowing, so "blocked" does not take effect until the guest's
        existing connection closes. Above it, the block applies to the
        traffic already in flight, which is what an operator pressing Block
        means.

        Placing a rule above the accepts is the dangerous direction in
        general -- §5.2.2 of that document says so, and a drop over the
        management tunnel is a router nobody can reach again. It is safe
        for *this* rule because it is not a general-purpose access rule: it
        matches ``dst-address-list=<content filter list>`` and nothing else,
        so it can only ever affect traffic to a destination the customer
        explicitly blocked. It cannot match the portal, the tunnel, or
        8728 unless one of those addresses is put in the block list.

        ## Convergence, and what is never touched

        ``librouteros`` exposes no ``move``, so correcting a misplaced rule
        is an ``add`` at the right position followed by a ``remove`` of the
        old row -- in that order, so the window has two identical DROPs
        rather than none. Duplicated drops are harmless; a gap is a site
        briefly unblocked, and this is a control that must fail closed.

        Only rows carrying this platform's own enforcement comment are ever
        added, moved or removed. No other rule in the chain is written,
        reordered, or read for permission. When ``forward`` has no
        ``accept`` at all there is nothing to sit above, so the rule is
        appended, which is where it already belongs.

        Still not claimed: that a marked packet reaches this chain at all on
        an arbitrary router. That is the ordered-band question §5.2 exists
        for, and it stays the firewall domain's to answer."""
        menu = api.path("ip", "firewall", "filter")
        forward = [
            row for row in menu if str(row.get("chain", "")) == "forward"
        ]

        ours = [
            row
            for row in forward
            if row.get("comment") == _CONTENT_FILTER_ENFORCEMENT_COMMENT
        ]
        anchor_index = next(
            (
                index
                for index, row in enumerate(forward)
                if str(row.get("action", "")) == "accept"
            ),
            None,
        )
        anchor_id = forward[anchor_index][".id"] if anchor_index is not None else None

        if ours:
            first_index = forward.index(ours[0])
            correctly_placed = anchor_index is None or first_index < anchor_index
            # More than one is not a state this method can produce, but a
            # half-finished reposition (or an older build) can leave one.
            extras = ours[1:]
            if correctly_placed and not extras:
                return
            if correctly_placed:
                for row in extras:
                    menu.remove(row[".id"])
                return

        self._add_content_filter_enforcement_rule(menu, anchor_id)
        # Add first, remove second: the chain is never left without a DROP.
        for row in ours:
            menu.remove(row[".id"])

    @staticmethod
    def _add_content_filter_enforcement_rule(menu, anchor_id: str | None) -> None:  # noqa: ANN001
        """The DROP itself, before ``anchor_id`` when there is one.

        ``place-before`` takes a ``.id`` (T1), so this passes the anchor
        row's own id rather than an index -- an index would go stale the
        moment the hotspot adds or removes one of its dynamic rules, which
        is the failure the ordering scheme exists to avoid.
        """
        fields = {
            "chain": "forward",
            "dst-address-list": _CONTENT_FILTER_ADDRESS_LIST_NAME,
            "action": "drop",
            "comment": _CONTENT_FILTER_ENFORCEMENT_COMMENT,
        }
        if anchor_id is not None:
            fields["place-before"] = anchor_id
        menu.add(**fields)

    # ------------------------------------------------------------------
    # QoS: the packet-mark half
    # ------------------------------------------------------------------

    async def configure_qos_packet_mark(
        self, creds: DeviceCredentials, *, rule: QosPacketMarkConfig
    ) -> None:
        """Realizes one QoS rule's ``/ip firewall mangle`` packet mark.

        ## Why this exists

        RouterOS realizes QoS as two independent objects, and this platform
        only ever wrote one of them on any path a customer can reach.
        :meth:`create_queue_tree` had a caller
        (``app.domains.qos.service.QosService.push_rule_to_device``); the
        mangle rule that *sets* the mark that queue references was rendered
        only into a config script. That script's push endpoint
        (``POST /network-config/routers/{router_id}/push``) *is*
        customer-reachable -- the reason it did not rescue QoS is transport,
        not routing: the script goes over SSH, and a port sweep run from the
        platform against a fleet router reached only ``8728``, with ``22``
        timing out alongside every other port tried, including one nothing
        listens on. The result on a real router was a queue tree matching
        zero packets, under a dashboard badge reading "Applied to your
        router". A mark with no queue is inert; a queue with no mark is
        equally inert, and harder to notice, because the object the
        platform records an id for does exist.

        ## The comment is the rule's identity

        ``"WyfyGuest qos <rule_id>: <label> (priority=<n>)"``, found again
        by the marker in front of the colon -- :meth:`configure_nat_masquerade`'s
        reasoning, unchanged. Nothing else on this rule can serve as the
        handle: ``protocol``/``dst-port``/``dscp`` *are* the classification
        the customer edits, and ``new-packet-mark`` is derived from the
        name they typed. Keyed on any of them, the push after an edit finds
        nothing, adds a second mangle rule, and leaves the first one still
        marking traffic for a classification nobody asked for -- silent,
        cumulative, and invisible in this platform's own UI.

        ## A re-typed rule is rewritten, not updated

        A rule that switched between a port-range match and a DSCP match is
        the one case where the fields to write are not the fields already
        there: leaving ``dst-port`` set on a rule that now matches by DSCP
        would keep matching the old ports. RouterOS has no "unset these
        fields" in an update the way it has an ``add``, so the old rule
        comes off before the new one goes on -- the same shape
        :meth:`configure_content_filter_rule` uses for a rule re-typed
        between a DNS sinkhole and an address list.

        ``disabled`` is normalized through :func:`_is_truthy`, never by
        string comparison, for the reason documented on
        :meth:`_ensure_dhcp_server`.

        ## Position in the chain: what this does NOT claim

        This appends to ``/ip firewall mangle`` and takes no view on where
        in the ``prerouting`` chain the rule lands, which is exactly what
        ``network_config.renderers.render_qos_traffic_rule``'s own
        ``/ip firewall mangle add`` has always done -- so a router pushed
        through this method carries the same rule in the same place as one
        pushed the script way, and no new ordering scheme is introduced
        here. Mangle is order-sensitive in the same way filter rules are
        (this rule sets ``passthrough=no``, so an earlier rule that matches
        the same packet and also stops pre-empts it), and the ordered-write
        design for that -- a sentinel band and ``place-before`` -- is
        specified in ``docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md``
        §5.2 and explicitly gated on two device tests (T1, T2) that have not
        been run. **Whether a marked packet actually reaches this rule on a
        given router is therefore unverified against hardware**, and is
        flagged here rather than assumed -- the same posture
        ``app.domains.qos.constants.QOS_QUEUE_TREE_PARENT`` already takes
        about ``parent=global``.

        Idempotent: re-pushing an unchanged rule writes nothing and raises
        nothing."""
        await asyncio.to_thread(self._configure_qos_packet_mark_sync, creds, rule)

    def _configure_qos_packet_mark_sync(
        self, creds: DeviceCredentials, rule: QosPacketMarkConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                desired = _qos_mangle_fields(rule)
                marker = _qos_marker(rule.rule_id)
                menu = api.path("ip", "firewall", "mangle")
                for row in list(menu):
                    if not str(row.get("comment", "")).startswith(marker):
                        continue
                    if any(
                        key not in desired and row.get(key) not in (None, "")
                        for key in _QOS_MANGLE_MATCH_FIELDS
                    ):
                        # Re-typed between a port-range match and a DSCP
                        # one -- see this method's own docstring.
                        menu.remove(row[".id"])
                        break
                    changed = {
                        key: value
                        for key, value in desired.items()
                        if str(row.get(key, "")) != value
                    }
                    if _is_truthy(row.get("disabled")):
                        changed["disabled"] = "no"
                    if changed:
                        menu.update(**{".id": row[".id"], **changed})
                    return
                menu.add(**desired, disabled="no")
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_qos_packet_mark: {exc}"
                ) from exc
        finally:
            api.close()

    async def delete_qos_packet_mark(
        self, creds: DeviceCredentials, *, rule_id: str
    ) -> None:
        """Removes one QoS rule's mangle mark, by the marker the write path
        stamped it with -- so a rule whose match was edited since its last
        push is still found.

        Without this, deleting a QoS rule removed its ``/queue tree`` entry
        and left the router marking packets for a rule the customer had
        deleted, until somebody re-pushed a whole config script. Idempotent:
        removing what is already absent is a no-op."""
        await asyncio.to_thread(self._delete_qos_packet_mark_sync, creds, rule_id)

    def _delete_qos_packet_mark_sync(
        self, creds: DeviceCredentials, rule_id: str
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                self._remove_where_prefixed(
                    api,
                    ("ip", "firewall", "mangle"),
                    "comment",
                    _qos_marker(rule_id),
                )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"delete_qos_packet_mark: {exc}"
                ) from exc
        finally:
            api.close()

    # ------------------------------------------------------------------
    # queue management (QoS/bandwidth shaping)
    # ------------------------------------------------------------------
    #
    # Ported from ``queue_management/device_adapters.py``. Every queue
    # operation is a native RouterOS API command (add/set/remove/print
    # over ``Path``) -- no SSH transport needed. RouterOS field names
    # containing a hyphen (``max-limit``, ``burst-limit``, ...) are passed
    # via ``**{"max-limit": ...}`` since they are not valid Python
    # keyword-argument identifiers -- identical to the original.

    def _queue_add_sync(
        self,
        creds: DeviceCredentials,
        path_segments: tuple[str, ...],
        fields: dict[str, str],
        operation: str,
    ) -> str:
        api = self._connect_api(creds)
        try:
            try:
                return api.path(*path_segments).add(**fields)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"{operation}: {exc}") from exc
        finally:
            api.close()

    def _queue_update_sync(
        self,
        creds: DeviceCredentials,
        path_segments: tuple[str, ...],
        fields: dict[str, str],
        operation: str,
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                api.path(*path_segments).update(**fields)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"{operation}: {exc}") from exc
        finally:
            api.close()

    def _queue_remove_sync(
        self,
        creds: DeviceCredentials,
        path_segments: tuple[str, ...],
        device_queue_id: str,
        operation: str,
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                api.path(*path_segments).remove(device_queue_id)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"{operation}: {exc}") from exc
        finally:
            api.close()

    async def create_simple_queue(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        target: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = 8,
    ) -> str:
        fields = {
            "name": name,
            "target": target,
            **_max_limit_field(upload_rate_kbps, download_rate_kbps),
            **_burst_fields(
                burst_upload_kbps,
                burst_download_kbps,
                burst_threshold_kbps,
                burst_time_seconds,
            ),
            "priority": str(priority),
        }
        return await asyncio.to_thread(
            self._queue_add_sync,
            creds,
            ("queue", "simple"),
            fields,
            "create_simple_queue",
        )

    async def update_simple_queue(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = 8,
    ) -> None:
        fields = {
            ".id": device_queue_id,
            **_max_limit_field(upload_rate_kbps, download_rate_kbps),
            **_burst_fields(
                burst_upload_kbps,
                burst_download_kbps,
                burst_threshold_kbps,
                burst_time_seconds,
            ),
            "priority": str(priority),
        }
        await asyncio.to_thread(
            self._queue_update_sync,
            creds,
            ("queue", "simple"),
            fields,
            "update_simple_queue",
        )

    async def delete_simple_queue(
        self, creds: DeviceCredentials, *, device_queue_id: str
    ) -> None:
        await asyncio.to_thread(
            self._queue_remove_sync,
            creds,
            ("queue", "simple"),
            device_queue_id,
            "delete_simple_queue",
        )

    async def create_queue_tree(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        parent: str,
        packet_mark: str | None,
        max_limit_kbps: int,
        priority: int = 8,
        queue_type_name: str | None = None,
    ) -> str:
        """Creates the ``/queue tree`` entry, or brings the entry already
        carrying ``name`` into line with these fields. Returns the
        device-side queue id either way.

        ## Why this reads before it writes

        This used to be a bare ``add``. Its only protection against a
        duplicate was the caller's own stored ``device_queue_id`` column,
        and a caller that lost that pointer -- which
        ``app.domains.qos.service`` did on every failed push, since the
        failure record was rolled back rather than committed -- could never
        push that rule again: RouterOS answers a duplicate ``add`` with
        "already have such item", forever, with no way out through the
        dashboard. Idempotency that lives only in the caller's database is
        not idempotency; it is a pointer that can be lost. ``name`` is the
        right key because that is what RouterOS itself treats as this row's
        identity, and this domain's names are deterministic
        (``cloudguest-qos-<rule id>``), never customer-typed.

        ## And why it updates rather than skipping

        ``priority`` and ``packet-mark`` are precisely what an edited rule
        changes; skipping would report success and leave the old values, the
        failure mode ``_ensure_ip_pool`` documents for address ranges.

        ``max-limit`` is compared as a *rate*, not as a string:
        ``"0k"`` goes out on the wire and ``0`` comes back, so a string
        comparison would find a difference on every single push and issue a
        pointless update forever -- the same trap :func:`_is_truthy` exists
        for on booleans. ``disabled`` goes through :func:`_is_truthy` for
        exactly that reason: an entry somebody disabled by hand is
        prioritising nothing, and a re-push is the operator asking for it
        again.

        Idempotent: re-pushing an unchanged queue writes nothing and raises
        nothing."""
        fields: dict[str, str] = {
            "name": name,
            "parent": parent,
            "max-limit": f"{max_limit_kbps}k",
            "priority": str(priority),
        }
        if packet_mark is not None:
            fields["packet-mark"] = packet_mark
        if queue_type_name is not None:
            fields["queue"] = queue_type_name
        return await asyncio.to_thread(
            self._ensure_queue_tree_sync, creds, name, fields
        )

    def _ensure_queue_tree_sync(
        self, creds: DeviceCredentials, name: str, fields: dict[str, str]
    ) -> str:
        api = self._connect_api(creds)
        try:
            try:
                menu = api.path("queue", "tree")
                for row in menu:
                    if row.get("name") != name:
                        continue
                    changed = {
                        key: value
                        for key, value in fields.items()
                        if _queue_tree_field_differs(key, row.get(key), value)
                    }
                    if _is_truthy(row.get("disabled")):
                        changed["disabled"] = "no"
                    if changed:
                        menu.update(**{".id": row[".id"], **changed})
                    return str(row[".id"])
                return menu.add(**fields, disabled="no")
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"create_queue_tree: {exc}"
                ) from exc
        finally:
            api.close()

    async def apply_pcq(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        rate_kbps: int,
        classifier: str = "dst-address",
    ) -> str:
        fields = {
            "name": name,
            "kind": "pcq",
            "pcq-rate": f"{rate_kbps}k",
            "pcq-classifier": classifier,
        }
        return await asyncio.to_thread(
            self._queue_add_sync, creds, ("queue", "type"), fields, "apply_pcq"
        )

    async def set_priority(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        priority: int,
        queue_kind: str = "simple",
    ) -> None:
        fields = {".id": device_queue_id, "priority": str(priority)}
        await asyncio.to_thread(
            self._queue_update_sync,
            creds,
            ("queue", queue_kind),
            fields,
            "set_priority",
        )

    async def assign_queue_to_target(
        self, creds: DeviceCredentials, *, device_queue_id: str, target: str
    ) -> None:
        fields = {".id": device_queue_id, "target": target}
        await asyncio.to_thread(
            self._queue_update_sync,
            creds,
            ("queue", "simple"),
            fields,
            "assign_queue_to_target",
        )

    async def remove_queue(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> None:
        await asyncio.to_thread(
            self._queue_remove_sync,
            creds,
            ("queue", queue_kind),
            device_queue_id,
            "remove_queue",
        )

    async def read_queue_status(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> QueueDeviceStatus:
        return await asyncio.to_thread(
            self._read_queue_status_sync, creds, queue_kind, device_queue_id
        )

    def _read_queue_status_sync(
        self, creds: DeviceCredentials, queue_kind: str, device_queue_id: str
    ) -> QueueDeviceStatus:
        api = self._connect_api(creds)
        try:
            try:
                rows = list(api.path("queue", queue_kind))
                row = next((r for r in rows if r.get(".id") == device_queue_id), {})
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"read_queue_status: {exc}"
                ) from exc
        finally:
            api.close()
        return QueueDeviceStatus(
            device_queue_id=device_queue_id,
            name=row.get("name"),
            target=row.get("target"),
            disabled=str(row.get("disabled", "false")).lower() == "true",
            bytes_uploaded=_split_pair_int(row.get("bytes"), 0),
            bytes_downloaded=_split_pair_int(row.get("bytes"), 1),
            packets_uploaded=_split_pair_int(row.get("packets"), 0),
            packets_downloaded=_split_pair_int(row.get("packets"), 1),
            queued_bytes=_split_pair_int(row.get("queued-bytes"), 0),
        )

    # ------------------------------------------------------------------
    # provisioning engine (discover/push/verify/health/backup/restore)
    # ------------------------------------------------------------------
    #
    # Ported from ``provisioning_engine/device_adapters.py``. Uses both
    # ``librouteros`` (structured discovery/health-check commands) and
    # ``asyncssh`` (file transfer + `/import`/`/system/backup/*` console
    # commands) -- see that module's own "why both librouteros AND
    # asyncssh" docstring, mirrored by this package's own module
    # docstring. Distinct from ``provision_device`` above (a different,
    # earlier-ported, more generic operation with its own filename) --
    # see ``_ssh_connect``'s own docstring for why these don't share code
    # with ``provision_device``.

    async def discover(self, creds: DeviceCredentials) -> DeviceDiscoveryResult:
        resource, routerboard, interfaces = await asyncio.to_thread(
            self._discover_sync, creds
        )
        return DeviceDiscoveryResult(
            vendor=self.vendor,
            model=routerboard.get("model"),
            serial_number=routerboard.get("serial-number"),
            firmware_version=resource.get("version"),
            cpu_load_percent=_as_float(resource.get("cpu-load")),
            free_memory_bytes=_as_int(resource.get("free-memory")),
            total_memory_bytes=_as_int(resource.get("total-memory")),
            uptime_seconds=_parse_routeros_uptime(resource.get("uptime")),
            interfaces=[i.get("name", "") for i in interfaces if i.get("name")],
            mac_address=interfaces[0].get("mac-address") if interfaces else None,
        )

    def _discover_sync(
        self, creds: DeviceCredentials
    ) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
        api = self._connect_api(creds)
        try:
            try:
                resource = next(iter(api("/system/resource/print")), {})
                routerboard = next(iter(api("/system/routerboard/print")), {})
                interfaces = list(api("/interface/print"))
                return resource, routerboard, interfaces
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"discover: {exc}") from exc
        finally:
            api.close()

    async def push_config(self, creds: DeviceCredentials, *, config_content: str) -> None:
        await self.upload_file(
            creds,
            filename=_PROVISIONING_ENGINE_CONFIG_FILENAME,
            content=config_content.encode("utf-8"),
        )
        await self._run_ssh_command(
            creds, f'/import file-name="{_PROVISIONING_ENGINE_CONFIG_FILENAME}"'
        )

    async def verify_config(
        self, creds: DeviceCredentials, *, expected_content: str
    ) -> bool:
        """Reads the config file back via SFTP and compares its SHA-256
        against ``expected_content`` -- ported from
        ``provisioning_engine/device_adapters.py::verify_config``."""
        uploaded = await self._download_file_via_sftp(
            creds, _PROVISIONING_ENGINE_CONFIG_FILENAME
        )
        expected_digest = hashlib.sha256(expected_content.encode("utf-8")).hexdigest()
        actual_digest = hashlib.sha256(uploaded).hexdigest()
        return expected_digest == actual_digest

    async def health_check(self, creds: DeviceCredentials) -> DeviceHealthResult:
        """Ported from
        ``provisioning_engine/device_adapters.py::health_check`` --
        **only** a connection failure is caught and reported as a graceful
        ``healthy=False`` result; a post-connection command failure
        (:class:`MikroTikDeviceError`, not the
        :class:`MikroTikConnectionError` subclass) is deliberately not
        caught here and propagates, exactly like the original."""
        try:
            resource = await asyncio.to_thread(self._health_check_sync, creds)
        except MikroTikConnectionError as exc:
            return DeviceHealthResult(
                healthy=False,
                cpu_load_percent=None,
                free_memory_bytes=None,
                uptime_seconds=None,
                detail=str(exc),
            )
        return DeviceHealthResult(
            healthy=True,
            cpu_load_percent=_as_float(resource.get("cpu-load")),
            free_memory_bytes=_as_int(resource.get("free-memory")),
            uptime_seconds=_parse_routeros_uptime(resource.get("uptime")),
        )

    def _health_check_sync(self, creds: DeviceCredentials) -> dict[str, object]:
        api = self._connect_api(creds)
        try:
            try:
                return next(iter(api("/system/resource/print")), {})
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"health_check: {exc}") from exc
        finally:
            api.close()

    async def backup(self, creds: DeviceCredentials) -> bytes:
        await self._run_ssh_command(
            creds, f'/system/backup/save name="{_PROVISIONING_ENGINE_BACKUP_FILENAME}"'
        )
        return await self._download_file_via_sftp(
            creds, _PROVISIONING_ENGINE_BACKUP_FILENAME
        )

    async def restore(self, creds: DeviceCredentials, *, backup_content: bytes) -> None:
        await self.upload_file(
            creds,
            filename=_PROVISIONING_ENGINE_BACKUP_FILENAME,
            content=backup_content,
        )
        await self._run_ssh_command(
            creds, f'/system/backup/load name="{_PROVISIONING_ENGINE_BACKUP_FILENAME}"'
        )

    async def upload_file(
        self, creds: DeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        try:
            async with (
                self._ssh_connect(creds) as conn,
                conn.start_sftp_client() as sftp,
                sftp.open(filename, "wb") as remote_file,
            ):
                await remote_file.write(content)
        except (OSError, asyncssh.Error) as exc:
            raise MikroTikConnectionError(creds.host, _describe_exception(exc)) from exc

    async def execute_raw_command(
        self, creds: DeviceCredentials, *, command: str
    ) -> RawCommandResult:
        """Ported from
        ``provisioning_engine/device_adapters.py::execute_raw_command`` --
        runs exactly ``command`` over the device's real SSH console
        connection with no interpretation, whitelisting, or retry. Unlike
        every other method here, a non-zero ``exit_status`` is not raised
        as an exception (see :class:`~.contract.RawCommandResult`'s own
        docstring)."""
        try:
            async with self._ssh_connect(creds) as conn:
                result = await conn.run(command, check=False)
        except (OSError, asyncssh.Error) as exc:
            raise MikroTikConnectionError(creds.host, _describe_exception(exc)) from exc
        return RawCommandResult(
            command=command,
            stdout=str(result.stdout or ""),
            stderr=str(result.stderr or ""),
            exit_status=result.exit_status if result.exit_status is not None else -1,
        )

    # ------------------------------------------------------------------
    # capability introspection
    # ------------------------------------------------------------------

    def capabilities(self) -> dict[str, bool]:
        return {
            "get_interface_list": True,
            "get_wan_health": True,
            "list_connected_devices": True,
            "provision_device": True,
            "reboot_device": True,
            "configure_vlan": True,
            "configure_vlan_hotspot": True,
            "delete_vlan_hotspot": True,
            "read_network_snapshot": True,
            "configure_dhcp_pool": True,
            "configure_port_forward": True,
            "delete_port_forward": True,
            "configure_nat_masquerade": True,
            "delete_nat_masquerade": True,
            "set_radius_client_config": True,
            "configure_content_filter_rule": True,
            "disconnect_device": True,
            "ping": True,
            "traceroute": True,
            "get_active_default_gateway": True,
            "get_pppoe_interface_status": True,
            "get_interface_traffic_counters": True,
            "run_speed_test": True,
            "create_simple_queue": True,
            "update_simple_queue": True,
            "delete_simple_queue": True,
            "create_queue_tree": True,
            "apply_pcq": True,
            "set_priority": True,
            "assign_queue_to_target": True,
            "remove_queue": True,
            "read_queue_status": True,
            "discover": True,
            "push_config": True,
            "verify_config": True,
            "health_check": True,
            "backup": True,
            "restore": True,
            "upload_file": True,
            "execute_raw_command": True,
        }


def _select_default_gateway(rows: list[dict[str, object]]) -> str | None:
    """Resolves the router's own currently-usable ``0.0.0.0/0`` gateway
    from a raw ``/ip/route`` reply -- shared by
    ``get_active_default_gateway``/``_get_active_default_gateway_sync``
    and ``_get_wan_health_sync`` so both read the exact same rule.

    Two-tier, in priority order:

    1. A genuinely *dynamic* default route (``dst-address == "0.0.0.0/0"``
       and ``dynamic == "true"``) -- RouterOS's own live, DHCP-negotiated
       gateway. This is the original, only-ever-implemented behavior,
       unchanged: if such a row exists it wins outright, on its own
       ``gateway`` field (even if that field is somehow empty -- an
       existing dynamic row is always authoritative over any fallback).

    2. Falls back to any other ``0.0.0.0/0`` route that is currently
       *active* and not administratively disabled -- static or otherwise.
       Required because this platform's own Setup Script generator
       (``buildRouterSetupScriptChunks`` in cloudguest-foundation's
       ``RouterDetailTabs.tsx``) deliberately sets
       ``add-default-route=no`` on every ``dhcp-client`` it creates and
       instead provisions a *static* ``0.0.0.0/0`` route with
       ``check-gateway=ping`` -- on purpose, to stop RouterOS's own
       dhcp-client-created dynamic route from silently fighting this
       platform's routing-mark/failover mangle rules. A router set up
       exactly as this platform's own generator intends therefore
       legitimately never has a ``dynamic=="true"`` default route at all,
       and tier 1 alone incorrectly reports every such DHCP-mode link as
       having no usable gateway (confirmed fleet-wide in production,
       2026-08-17, router "gurugram": a since-fixed, unrelated bug had
       been leaving a stray leftover ``dhcp-client`` on some routers that
       happened to create an accidental dynamic route, silently masking
       this pre-existing one everywhere it occurred -- removing that
       stray client surfaced the underlying bug immediately).

       ``active`` -- not ``disabled`` alone -- is RouterOS's own real,
       live "is this route actually the one currently forwarding matching
       traffic" flag: it goes false the instant a ``check-gateway`` probe
       on that route fails, independent of the ``disabled`` admin flag.
       Requiring ``active == "true"`` here (rather than merely "this row
       exists") is what keeps a real outage -- a static default route
       whose gateway has genuinely stopped responding to ``check-gateway``
       -- correctly reported as unavailable rather than masked by this
       fallback.

    Deliberately never filtered by interface name in either tier -- see
    ``get_active_default_gateway``'s own docstring for why."""
    gateway, _interface = _select_default_route(rows)
    return gateway


def _select_default_route(
    rows: list[dict[str, object]],
) -> tuple[str | None, str | None]:
    """Same two-tier rule as :func:`_select_default_gateway`, additionally
    returning the RouterOS ``interface`` field of whichever row the
    gateway came from (``None`` if no usable default route was found, or
    the winning row simply has no ``interface`` field) -- used by
    ``_get_wan_health_sync``, which also needs to know *which* interface
    the default route rides on to resolve PPPoE status/traffic counters
    against it."""
    winning_row = _select_default_route_row(rows)
    if winning_row is None:
        return None, None
    gateway = winning_row.get("gateway")
    interface = winning_row.get("interface")
    return (
        str(gateway) if gateway else None,
        str(interface) if interface else None,
    )


def _select_default_route_row(
    rows: list[dict[str, object]],
) -> dict[str, object] | None:
    """The raw ``/ip/route`` row the two-tier rule above selects, or
    ``None``.

    Extracted so WAN-interface resolution reads the *same* winning route
    as the gateway/health reads rather than re-implementing the choice --
    it needs fields (``immediate-gw``) the two-value view above does not
    carry, and a second copy of "which default route counts" is exactly
    the kind of drift that produced the 2026-08-17 incident."""
    dynamic_row: dict[str, object] | None = None
    active_fallback_row: dict[str, object] | None = None
    for row in rows:
        if row.get("dst-address") != "0.0.0.0/0":
            continue
        is_dynamic = str(row.get("dynamic", "false")).lower() == "true"
        if is_dynamic:
            dynamic_row = row
            break
        if active_fallback_row is not None:
            continue
        is_active = str(row.get("active", "false")).lower() == "true"
        is_disabled = str(row.get("disabled", "false")).lower() == "true"
        if is_active and not is_disabled and row.get("gateway"):
            active_fallback_row = row
    return dynamic_row if dynamic_row is not None else active_fallback_row


def _gateway_address(value: object) -> str | None:
    """The bare gateway IP from a RouterOS gateway token.

    RouterOS v7 qualifies a gateway with the interface it is reachable on
    -- ``"192.168.1.1%ether1"`` -- in ``gateway`` and ``immediate-gw``
    alike. Everything that has to *match* the gateway against something
    else (an address's subnet, a dhcp-client's own gateway) needs the
    address half alone."""
    text = _safe_str(value)
    if not text:
        return None
    return text.split("%", 1)[0].strip() or None


def _gateway_token_interface(value: object) -> str | None:
    """The interface half of that same token, when RouterOS supplies one
    -- the device naming its own egress interface for this route."""
    text = _safe_str(value)
    if not text or "%" not in text:
        return None
    return text.split("%", 1)[1].strip() or None


def _interface_holding_gateway(
    gateway: str | None, address_rows: list[dict[str, object]]
) -> str | None:
    """The interface carrying an address whose subnet contains
    ``gateway``.

    A derivation rather than a heuristic: a next-hop gateway is reachable
    precisely because the router holds an address in its subnet, and the
    interface that address is on is the one traffic to it leaves by. This
    is the tier that resolves an ordinary DHCP-WAN router, whose default
    route names no interface of its own."""
    if not gateway:
        return None
    try:
        gateway_ip = ipaddress.ip_address(gateway)
    except ValueError:
        return None
    for row in address_rows:
        address = _safe_str(row.get("address"))
        interface = _safe_str(row.get("interface"))
        if not address or not interface:
            continue
        try:
            network = ipaddress.ip_interface(address).network
        except ValueError:
            continue
        if gateway_ip in network:
            return interface
    return None


def _dhcp_client_interface_for_gateway(
    gateway: str | None, dhcp_client_rows: list[dict[str, object]]
) -> str | None:
    """The interface of the ``/ip dhcp-client`` that negotiated exactly
    this gateway.

    Matched on the gateway, never on "there is only one dhcp-client": a
    router with a second dhcp-client on an internal link would otherwise
    have guest traffic masqueraded onto that internal segment."""
    if not gateway:
        return None
    for row in dhcp_client_rows:
        interface = _safe_str(row.get("interface"))
        if interface and _gateway_address(row.get("gateway")) == gateway:
            return interface
    return None


def _select_wan_interface(
    route_rows: list[dict[str, object]],
    address_rows: list[dict[str, object]],
    dhcp_client_rows: list[dict[str, object]],
    interface_names: set[str],
) -> str | None:
    """The WAN-facing interface name, or ``None`` when the router's own
    live state does not honestly identify one.

    The full rule -- which default route counts, the four ordered ways to
    name its interface, and what is deliberately not used -- is documented
    on :meth:`MikroTikAdapter.resolve_wan_interface`. This function is
    that rule with no I/O in it, so it can be reasoned about (and tested)
    against raw RouterOS reply rows.

    Every candidate is checked against ``interface_names`` before it wins,
    so a stale name in a route row can never become an ``out-interface``
    referring to an interface this device does not have."""
    row = _select_default_route_row(route_rows)
    if row is None:
        return None
    return _route_interface(row, address_rows, dhcp_client_rows, interface_names)


def _route_interface(
    row: dict[str, object],
    address_rows: list[dict[str, object]],
    dhcp_client_rows: list[dict[str, object]],
    interface_names: set[str],
) -> str | None:
    """The egress interface of ONE route row -- the four ordered tiers
    documented on :meth:`MikroTikAdapter.resolve_wan_interface`, with no
    opinion about which route is the important one.

    Split out of :func:`_select_wan_interface` when WAN failover needed the
    same naming rule applied to *every* default route rather than only to
    the winning one. Deliberately not a second copy: a failover that named
    interfaces by one rule while ``resolve_wan_interface`` (and therefore
    every NAT push) named them by another would put the masquerade on one
    interface and the route on a different one, and each would look correct
    on its own.

    Every candidate is checked against ``interface_names`` before it wins,
    so a stale name in a route row can never become an ``out-interface``
    referring to an interface this device does not have."""
    gateway = _gateway_address(row.get("gateway"))
    candidates = (
        _safe_str(row.get("interface")),
        _gateway_token_interface(row.get("immediate-gw")),
        _gateway_token_interface(row.get("gateway")),
        _interface_holding_gateway(gateway, address_rows),
        _dhcp_client_interface_for_gateway(gateway, dhcp_client_rows),
    )
    for candidate in candidates:
        if candidate and candidate in interface_names:
            return candidate
    return None


def _is_main_table_row(row: dict[str, object]) -> bool:
    """Whether a ``/ip route`` row lives in the ``main`` routing table.

    RouterOS omits the property on an unmarked route rather than spelling
    out ``"main"``, so absent means main. The filter matters because this
    module's own caller (``network_config/wan/renderers.py``) provisions a
    ``routing-table="to_wan<N>"`` default route *per WAN* plus a
    ``distance=2`` crossover backup in load-balance mode. Those are active
    in their own tables simultaneously; counting them as candidates would
    make every load-balanced router look permanently ambiguous."""
    table = _safe_str(row.get("routing-table"))
    return table is None or table == "main"


def _build_rogue_dhcp_alert_statuses(
    alert_rows: list[dict[str, object]],
    dhcp_serving_interfaces: set[str],
) -> list[RogueDhcpAlertStatus]:
    """One :class:`RogueDhcpAlertStatus` per interface, from the union of
    the alert rows and the interfaces actually serving DHCP.

    The union, not the alert rows alone: an interface handing out
    addresses with no alert on it is precisely the thing a caller asks
    this question to find, and it has no row to be listed by. Pure, and
    module-level, so the shape of the answer is testable without a
    transport at all -- ``_build_default_routes``'s precedent.

    Sorted by interface name so a caller diffing two reads, or a test
    asserting on one, is not comparing against RouterOS's row order.
    """
    statuses: dict[str, RogueDhcpAlertStatus] = {}
    for row in alert_rows:
        interface = _safe_str(row.get("interface"))
        if interface is None:
            # A row that names no interface watches nothing identifiable;
            # reporting it under a made-up name would be worse than
            # leaving it out.
            continue
        statuses[interface] = RogueDhcpAlertStatus(
            interface=interface,
            serves_dhcp=interface in dhcp_serving_interfaces,
            alert_present=True,
            # RouterOS answers with a real bool and accepts "no" on write;
            # see ``_is_truthy``.
            enabled=not _is_truthy(row.get("disabled")),
            valid_servers=_split_valid_servers(row.get("valid-server")),
            alert_timeout=_safe_str(row.get("alert-timeout")),
            managed=_safe_str(row.get("comment")) == _ROGUE_DHCP_ALERT_COMMENT,
            unknown_server=_safe_str(row.get("unknown-server")),
        )
    for interface in dhcp_serving_interfaces:
        if interface in statuses:
            continue
        statuses[interface] = RogueDhcpAlertStatus(
            interface=interface,
            serves_dhcp=True,
            alert_present=False,
            enabled=False,
            valid_servers=(),
            alert_timeout=None,
            managed=False,
            unknown_server=None,
        )
    return [statuses[name] for name in sorted(statuses)]


def _build_default_routes(
    route_rows: list[dict[str, object]],
    address_rows: list[dict[str, object]],
    dhcp_client_rows: list[dict[str, object]],
    interface_names: set[str],
) -> list[DefaultRoute]:
    """Every ``0.0.0.0/0`` row in the ``main`` table, as
    :class:`~.contract.DefaultRoute` values.

    No I/O, so the whole failover decision can be reasoned about (and
    tested) against raw RouterOS reply rows. Nothing is filtered out for
    being inactive or disabled: "the backup route exists but RouterOS has
    stopped considering it active" is precisely the fact a caller has to
    see before it moves traffic onto it, and dropping such rows here would
    turn a refusal into a route-not-found."""
    routes: list[DefaultRoute] = []
    for row in route_rows:
        if row.get("dst-address") != "0.0.0.0/0" or not _is_main_table_row(row):
            continue
        route_id = _safe_str(row.get(".id"))
        if route_id is None:
            # No handle to address it by, so no write could ever target it.
            # Reporting it as a candidate would let a caller select a route
            # it cannot then move.
            continue
        routes.append(
            DefaultRoute(
                route_id=route_id,
                gateway=_gateway_address(row.get("gateway")),
                interface=_route_interface(
                    row, address_rows, dhcp_client_rows, interface_names
                ),
                distance=_safe_int(row.get("distance")),
                active=_is_truthy(row.get("active")),
                disabled=_is_truthy(row.get("disabled")),
                dynamic=_is_truthy(row.get("dynamic")),
                comment=_safe_str(row.get("comment")),
            )
        )
    return routes


def _parse_ping_rows(
    rows: list[dict[str, object]], *, requested_count: int
) -> tuple[int, int, float, float | None]:
    """Ported verbatim (in spirit) from ``isp/device_adapters.py``/
    ``network_diagnostics/device_adapters.py``'s identical
    ``_parse_ping_rows`` -- the last yielded row of a completed
    ``/tool/ping`` carries the cumulative ``sent``/``received``/
    ``packet-loss``/``avg-rtt`` fields. An empty ``rows`` list (no reply at
    all) is treated as total, 100% loss -- never silently reported as "no
    data". Returns ``(sent, received, packet_loss_percentage,
    avg_rtt_ms)``."""
    if not rows:
        return requested_count, 0, 100.0, None
    last = rows[-1]
    sent = _safe_int(last.get("sent"), default=requested_count) or requested_count
    received = _safe_int(last.get("received"), default=0) or 0
    packet_loss = _safe_float(last.get("packet-loss"), default=None)
    if packet_loss is None:
        packet_loss = 100.0 * (1 - received / sent) if sent else 100.0
    avg_rtt_ms = _parse_routeros_duration_ms(last.get("avg-rtt"))
    return sent, received, packet_loss, avg_rtt_ms


def _parse_traceroute_rows(rows: list[dict[str, object]]) -> list[TracerouteHop]:
    """Ported verbatim from
    ``network_diagnostics/device_adapters.py::_parse_traceroute_rows`` --
    collapses consecutive same-``address`` reply rows into one final
    :class:`TracerouteHop` each, numbering hops by position in the reply
    stream (RouterOS's own traceroute does not number hops as an explicit
    reply field)."""
    hops: list[TracerouteHop] = []
    current_address: object = object()  # sentinel matching no real address
    for row in rows:
        address = row.get("address") or None
        if address != current_address or not hops:
            hops.append(_build_hop(len(hops) + 1, row))
            current_address = address
        else:
            hops[-1] = _build_hop(hops[-1].hop_number, row)
    return hops


def _build_hop(hop_number: int, row: dict[str, object]) -> TracerouteHop:
    address = row.get("address")
    loss_default = 100.0 if not address else 0.0
    return TracerouteHop(
        hop_number=hop_number,
        address=str(address) if address else None,
        packet_loss_percentage=_safe_float(row.get("loss"), default=loss_default)
        or loss_default,
        avg_rtt_ms=_parse_routeros_duration_ms(row.get("avg")),
    )


def _max_limit_field(upload_rate_kbps: int, download_rate_kbps: int) -> dict[str, str]:
    """Ported verbatim from
    ``queue_management/device_adapters.py::_max_limit_field``."""
    return {"max-limit": f"{upload_rate_kbps}k/{download_rate_kbps}k"}


def _burst_fields(
    burst_upload_kbps: int | None,
    burst_download_kbps: int | None,
    burst_threshold_kbps: int | None,
    burst_time_seconds: int | None,
) -> dict[str, str]:
    """Ported verbatim from
    ``queue_management/device_adapters.py::_burst_fields`` -- RouterOS
    only accepts burst-limit/burst-threshold/burst-time as a trio; if
    neither burst rate value is set, no burst fields are emitted at all."""
    if burst_upload_kbps is None and burst_download_kbps is None:
        return {}
    fields = {
        "burst-limit": f"{burst_upload_kbps or 0}k/{burst_download_kbps or 0}k",
    }
    if burst_threshold_kbps is not None:
        fields["burst-threshold"] = f"{burst_threshold_kbps}k/{burst_threshold_kbps}k"
    if burst_time_seconds is not None:
        fields["burst-time"] = f"{burst_time_seconds}/{burst_time_seconds}"
    return fields


def _split_pair_int(value: object, index: int) -> int | None:
    """Ported verbatim from
    ``queue_management/device_adapters.py::_split_pair_int`` -- RouterOS
    reports several counters (``bytes``, ``packets``, ``queued-bytes``) as
    an ``"upload/download"``-style pair string."""
    if not value:
        return None
    parts = str(value).split("/")
    if len(parts) <= index:
        return None
    try:
        return int(parts[index])
    except ValueError:
        return None


def _as_float(value: object) -> float | None:
    """Ported verbatim from
    ``provisioning_engine/device_adapters.py::_as_float`` -- strips a
    trailing ``%`` (RouterOS's own ``cpu-load`` reply shape), unlike
    :func:`_safe_float` above (which has no such stripping and is used by
    the isp/network_diagnostics ping/duration parsing this module also
    ports)."""
    if value is None:
        return None
    try:
        return float(str(value).rstrip("%"))
    except ValueError:
        return None


def _as_int(value: object) -> int | None:
    """Ported verbatim from
    ``provisioning_engine/device_adapters.py::_as_int``."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_routeros_uptime(value: object) -> int | None:
    """Ported verbatim from
    ``provisioning_engine/device_adapters.py::_parse_routeros_uptime`` --
    RouterOS reports uptime as e.g. ``"3w2d4h5m6s"``, not a raw number of
    seconds (distinct format/parser from
    :func:`_parse_routeros_duration_ms` above, which parses a different
    real RouterOS string shape used by ping/traceroute reply fields)."""
    if not value:
        return None
    text = str(value)
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total_seconds = 0
    number = ""
    for char in text:
        if char.isdigit():
            number += char
        elif char in units and number:
            total_seconds += int(number) * units[char]
            number = ""
        else:
            return None
    return total_seconds


def _row_mac(row: dict[str, object]) -> str | None:
    return normalize_mac_address(row.get("mac-address"))


def _parse_signal_strength(value: object) -> int | None:
    """Ported verbatim from
    ``connected_devices/device_adapters.py::_parse_signal_strength`` --
    RouterOS reports signal strength as e.g. ``"-55dBm@6Mbps"`` or plain
    ``"-55"`` depending on version."""
    if value is None:
        return None
    text = str(value)
    digits = ""
    for index, char in enumerate(text):
        if (char in "+-" and index == 0) or char.isdigit():
            digits += char
        else:
            break
    try:
        return int(digits)
    except ValueError:
        return None


def _merge_connected_devices(
    leases: list[dict[str, object]],
    arp_entries: list[dict[str, object]],
    wireless_entries: list[dict[str, object]],
) -> list[ConnectedDevice]:
    """Ported verbatim from
    ``connected_devices/device_adapters.py::_merge_discovered_devices`` --
    merges DHCP-lease/ARP/wireless-registration-table replies into one
    :class:`ConnectedDevice` per MAC address. See that module's own
    docstring for why each menu answers a different question about the
    same device and why a device present in more than one source is never
    duplicated."""
    wireless_by_mac: dict[str, dict[str, object]] = {}
    for row in wireless_entries:
        mac = _row_mac(row)
        if mac is not None:
            wireless_by_mac[mac] = row

    merged: dict[str, ConnectedDevice] = {}

    for row in arp_entries:
        mac = _row_mac(row)
        if mac is None:
            continue
        merged[mac] = ConnectedDevice(
            mac_address=mac,
            ip_address=_safe_str(row.get("address")),
            hostname=None,
            interface=_safe_str(row.get("interface")),
            is_wireless=mac in wireless_by_mac,
            signal_strength_dbm=None,
        )

    for row in leases:
        mac = _row_mac(row)
        if mac is None:
            continue
        existing = merged.get(mac)
        merged[mac] = ConnectedDevice(
            mac_address=mac,
            ip_address=_safe_str(row.get("active-address") or row.get("address"))
            or (existing.ip_address if existing else None),
            hostname=_safe_str(row.get("host-name")),
            interface=_safe_str(row.get("interface"))
            or (existing.interface if existing else None),
            is_wireless=mac in wireless_by_mac,
            signal_strength_dbm=existing.signal_strength_dbm if existing else None,
        )

    for mac, row in wireless_by_mac.items():
        existing = merged.get(mac)
        merged[mac] = ConnectedDevice(
            mac_address=mac,
            ip_address=existing.ip_address if existing else None,
            hostname=existing.hostname if existing else None,
            interface=_safe_str(row.get("interface"))
            or (existing.interface if existing else None),
            is_wireless=True,
            signal_strength_dbm=_parse_signal_strength(row.get("signal-strength")),
        )

    return list(merged.values())


__all__ = [
    "MikroTikAdapter",
    "MikroTikDeviceError",
    "MikroTikConnectionError",
    "normalize_mac_address",
]

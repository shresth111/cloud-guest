"""The ONE stable contract the main cloud-guest-repo backend depends on.

Nothing in cloud-guest-repo should ever import a vendor-specific adapter
directly -- only this module's types and ``get_adapter()`` (in
``wyfy_device_gateway.registry``).

This is a near-verbatim implementation of PRD section 4.1's illustrative
contract. ``StrEnum`` requires Python 3.11+; this package (like
cloud-guest-repo's own backend) targets Python 3.13+ (see pyproject.toml),
so no compatibility shim is needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable


class DeviceVendor(StrEnum):
    MIKROTIK = "mikrotik"
    TPLINK_OMADA = "tplink_omada"
    RUCKUS = "ruckus"
    UNIFI = "unifi"
    ARUBA = "aruba"
    CISCO_MERAKI = "cisco_meraki"
    # add here as real adapters land; UnsupportedVendorError otherwise


class UnsupportedVendorError(Exception):
    """Raised by ``get_adapter`` when no adapter is registered for a
    vendor. Mirrors the ``UnsupportedXVendorError`` exceptions already
    raised six times over in cloud-guest-repo (PRD section 2.1) --
    consolidated here into the one real copy."""

    def __init__(self, vendor: object) -> None:
        self.vendor = vendor
        super().__init__(f"no device gateway adapter registered for vendor: {vendor!r}")


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """Resolved, already-decrypted per-device connection material. Built by
    the CALLER (cloud-guest-repo) from Router.management_ip_address /
    api_username / decrypted api_credentials_encrypted -- the Gateway never
    touches Fernet or the DB directly. See PRD section 6."""

    vendor: DeviceVendor
    host: str
    username: str
    secret: str  # password, API key, or token depending on vendor
    port: int | None = None          # vendor-specific default if None
    timeout_seconds: int = 10
    extra: dict[str, str] = field(default_factory=dict)  # e.g. Omada site id,
    # UniFi controller base URL, Meraki org/network id -- whatever a given
    # vendor's connection needs beyond host/user/secret. Kept generic and
    # opaque to the caller on purpose: cloud-guest-repo should never need to
    # know what's inside `extra` for a vendor it isn't actively using.


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    has_ip_address: bool
    # Whether this interface is a *member port* of some bridge, as opposed
    # to being a bridge itself. ``bridge`` already carries which bridge, so
    # this is derivable -- but only for a caller that knows the convention,
    # and a VLAN access port picker needs the fact directly: an access port
    # has to be a bridge port to be pulled out of one. Defaulted so the
    # several existing constructors of this shape keep working unchanged.
    is_bridge_port: bool = False


@dataclass(frozen=True, slots=True)
class IpAddressInfo:
    """One row of the device's own ``/ip address`` table.

    Read, never written, by the callers of :class:`NetworkSnapshot`. The
    subnet a VLAN is about to claim has to be checked against what the
    router already carries -- other VLAN *rows* in this platform's database
    are not the same set, and are not the set RouterOS will reject against.
    """

    address: str  # "192.168.10.1/24" -- an address with a prefix, not a network
    interface: str | None
    disabled: bool


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    """Everything a VLAN preflight needs, read in one connection.

    Deliberately one shape rather than two calls. "Is the router
    reachable", "does the parent interface exist", and "does this subnet
    collide with something already on the device" are three questions with
    one answer source, and asking them over three separate RouterOS
    sessions triples the time an operator waits for a validation failure --
    and makes it possible for the three answers to disagree.
    """

    interfaces: list[InterfaceInfo]
    ip_addresses: list[IpAddressInfo]


@dataclass(frozen=True, slots=True)
class WanHealth:
    reachable: bool
    # Name kept for shape stability even though the value is no longer
    # necessarily a *dynamic* route's gateway -- see
    # ``DeviceGatewayAdapter.get_active_default_gateway``'s own docstring:
    # falls back to an active *static* default route's gateway when no
    # dynamic one exists (the common case for a router provisioned by
    # this platform's own Setup Script generator).
    dynamic_gateway: str | None
    ppp_status: bool | None
    rx_bytes: int | None
    tx_bytes: int | None
    latency_ms: float | None
    packet_loss_percent: float | None


@dataclass(frozen=True, slots=True)
class ConnectedDevice:
    mac_address: str
    ip_address: str | None
    hostname: str | None
    interface: str | None
    is_wireless: bool
    signal_strength_dbm: int | None


@dataclass(frozen=True, slots=True)
class VlanConfig:
    """One VLAN to realize on a device.

    ``port_mode`` mirrors ``app.domains.vlan.models.Vlan.port_mode`` and
    changes what is created, not merely how it looks:

    * ``"trunk"`` -- ``interface`` is the parent trunk carrying tagged
      traffic; a ``/interface vlan`` sub-interface named ``vlan<id>`` is
      created on it and the address goes there.
    * ``"access"`` -- ``interface`` is a dedicated *physical* port. It is
      pulled out of the shared bridge and given this VLAN's subnet
      directly, untagged. No ``/interface vlan`` entry is created at all.

    Getting this wrong is not cosmetic: a row the operator saved as
    "access" but realized as trunk leaves that physical port on the wrong
    network. See ``network_config.renderers.render_vlan``, which this
    mirrors.
    """

    vlan_id: int
    name: str
    interface: str
    ip_cidr: str | None
    port_mode: str = "trunk"


@dataclass(frozen=True, slots=True)
class VlanHotspotConfig:
    """One VLAN's own standalone captive portal.

    Mirrors ``network_config.renderers._render_vlan_hotspot`` command for
    command: an ``/ip pool``, an ``/ip dhcp-server`` and its network row,
    an ``/ip hotspot profile``, an ``/ip dns static`` record for that
    profile's ``dns-name``, and the ``/ip hotspot`` server itself -- all
    bound to ``interface`` and named after ``vlan_id``, so one VLAN's
    portal cannot touch another's or the router's own default ``hotspot1``.

    ``interface`` is the *bind* interface, which is not always
    ``vlan<id>``: in access mode the VLAN is realized as a physical port
    with no ``/interface vlan`` entry at all, and the portal belongs on
    that port. The caller resolves it; this shape does not guess.

    ``gateway`` is required, not optional as it is on ``VlanConfig``. A
    portal has to hand out addresses and answer DNS on a real address of
    its own, and ``_render_vlan_hotspot`` skips with an explanatory comment
    rather than inventing one -- the direct-push equivalent is the caller
    refusing before it connects.
    """

    vlan_id: int
    interface: str
    cidr: str
    gateway: str
    # The ``dns-name`` RouterOS puts in the portal redirect URL, and the
    # ``/ip dns static`` name that makes it resolve. Passed in rather than
    # built here: the platform-wide base name lives in
    # ``network_config.renderers.HOTSPOT_DNS_NAME`` and this package cannot
    # import ``app.domains`` (see the module docstring).
    dns_name: str
    # RouterOS's ``html-directory`` -- which uploaded portal page set this
    # profile serves. Same reasoning as ``dns_name``.
    html_directory: str


@dataclass(frozen=True, slots=True)
class DhcpPoolConfig:
    interface: str
    range_start: str
    range_end: str
    gateway: str
    dns_servers: list[str]
    lease_time_seconds: int


@dataclass(frozen=True, slots=True)
class PortForwardConfig:
    """One inbound port-forwarding (DSTNAT) rule to realize on a device.

    Sibling of :class:`NatRuleConfig` -- both land in ``/ip firewall nat``,
    but on opposite chains and in opposite directions
    (``dstnat``/``dst-nat`` inbound here, ``srcnat``/``masquerade``
    outbound there) -- and it carries its identity for the same reason.

    ``rule_id`` is the caller's own stable handle for this rule (the
    ``port_forwarding_rules`` row id), carried for identity and written to
    no RouterOS field except the comment. Every *other* field here is one a
    customer edits in the dashboard: the external port they publish, the
    host behind it, its port, the protocol. Keying the rule on any of them
    means the next push finds no match, adds a second rule, and leaves the
    first one still forwarding the same public port to a host that may no
    longer be there -- silent, cumulative, and invisible in this platform's
    own UI. See ``mikrotik_adapter.configure_port_forward``.

    ``protocol`` accepts ``"both"`` in addition to ``"tcp"``/``"udp"``,
    because that is what the domain's own rules can say. RouterOS cannot
    express it on a single rule (``dst-port`` is only valid alongside a
    tcp/udp ``protocol``), so the vendor adapter realizes it as one device
    rule per transport -- see that method's docstring.

    ``dst_address``/``src_address`` are ``None`` for "any", matching the
    nullable columns they come from. ``src_address`` in particular is a
    restriction: dropping it on the way to the device would publish a port
    the operator meant to expose to one network to the whole internet.
    """

    rule_id: str
    protocol: str  # "tcp" | "udp" | "both"
    external_port: int
    internal_ip: str
    internal_port: int
    dst_address: str | None = None
    src_address: str | None = None


@dataclass(frozen=True, slots=True)
class QosPacketMarkConfig:
    """One QoS traffic-classification rule's ``/ip firewall mangle``
    packet mark -- the half of RouterOS QoS that actually selects packets.

    RouterOS realizes QoS as two independent objects: a mangle rule that
    *sets* a packet mark, and a ``/queue tree`` entry that *references* it.
    A queue referencing a mark nothing sets is inert, and that was exactly
    the shipped state: ``create_queue_tree`` had a caller, this had no
    equivalent at all, so the live push wrote the queue half and nothing
    else.

    The mangle line was not missing from the codebase -- ``network_config``
    renders it (``renderers.render_qos_traffic_rule``) into the combined
    config script, and ``POST /network-config/routers/{id}/push`` is
    customer-reachable. It does not rescue QoS, because that script is
    delivered over SSH, and a port sweep run from the platform against a
    fleet router reached **only** ``8728``: ``22`` times out, along with
    every other port tried including one nothing listens on, so the
    filtering sits upstream of the router rather than on it. Both halves
    therefore failed at once -- the half this class fixes was never called,
    and the half that existed could not be delivered. The dashboard said
    "Applied to your router" over the top of that.

    ``rule_id`` is carried for identity, not for any RouterOS field, for
    the same reason it is on :class:`ContentFilterRuleConfig` and
    :class:`PortForwardConfig`: ``protocol``/``port_range_*``/``dscp_value``
    are precisely what a customer edits, and ``label`` is the name they
    typed. Keyed on any of them, the push after an edit would find no
    match, add a second mangle rule, and leave the first one still marking
    traffic for a classification nobody asked for.

    ``packet_mark`` is the caller's own identifier and must be the exact
    string the paired ``/queue tree`` entry references -- the two are
    derived from one source of truth on the caller's side
    (``app.domains.qos.identifiers.qos_packet_mark_identifier``), because
    two independently-derived strings that drift apart fail silently: both
    objects exist, neither does anything.

    The match is either a protocol/port-range pair or a DSCP value, never
    both and never neither -- the caller's own validator enforces that
    (``app.domains.qos.validators.validate_traffic_match``), and a rule
    that switched from one to the other is torn down and rewritten rather
    than updated in place, because the fields the old match used have to
    stop matching.
    """

    rule_id: str  # this rule's own stable id, and its device-side identity
    packet_mark: str  # the mark this rule sets, and the queue tree reads
    label: str  # human-readable label, carried in the device's own comment
    priority: int  # carried in the comment only -- the queue tree sets it
    protocol: str | None = None  # "tcp"/"udp", with a port range
    port_range_start: int | None = None
    port_range_end: int | None = None
    dscp_value: int | None = None  # the alternative match, 0-63


@dataclass(frozen=True, slots=True)
class NatRuleConfig:
    """One VLAN's source-NAT (masquerade) rule -- what turns a routed but
    isolated VLAN subnet into one whose guests actually reach the
    internet.

    Sibling of :class:`PortForwardConfig`: both land in ``/ip firewall
    nat``, but on opposite chains and in opposite directions
    (``dstnat``/``dst-nat`` inbound there, ``srcnat``/``masquerade``
    outbound here).

    ``vlan_id`` is carried for identity, not for any RouterOS field: the
    rule is found again on a later push by the comment derived from it
    (``"WyfyGuest VLAN <id>"``), because ``src_address`` is precisely the
    field an operator edits and so cannot be the handle -- see
    ``mikrotik_adapter.configure_nat_masquerade``'s own docstring.

    ``out_interface`` is ``None`` by default and that is the normal case:
    it means "whichever interface this router's own live default route
    leaves by". The caller (cloud-guest-repo) has no honest way to know a
    given router's WAN port -- it is not stored anywhere, differs per
    site, and a hardcoded ``"WAN"``/``"ether1"`` would masquerade out of
    the wrong interface or silently match nothing. Pass a real name only
    to override that resolution deliberately.
    """

    vlan_id: int
    src_address: str  # the VLAN's own subnet as a CIDR, e.g. "10.100.0.0/24"
    out_interface: str | None = None


@dataclass(frozen=True, slots=True)
class RadiusClientConfig:
    radius_server_host: str
    radius_secret: str
    auth_port: int = 1812
    acct_port: int = 1813


@dataclass(frozen=True, slots=True)
class ContentFilterRuleConfig:
    """One content-filtering rule to realize on the device -- either a
    domain to DNS-sinkhole or an IP/CIDR to address-list-and-drop. See
    ``mikrotik_adapter.py``'s ``configure_content_filter_rule`` docstring
    for the real RouterOS mechanism and its honest limits (DNS-based
    blocking only, no Layer7, no web-proxy, no TLS interception -- see
    that docstring's own "Honest scope" section). Ported from
    ``cloud-guest-repo/backend/app/domains/content_filtering`` (see that
    domain's own module docstring for the full customer-facing scope
    write-up this vendor-agnostic shape mirrors).

    ``rule_id`` is carried for identity, not for any RouterOS field: the
    objects this rule becomes are found again on a later push by the
    comment marker derived from it, because ``value`` -- the blocked
    domain or address -- is precisely what a customer edits and so cannot
    be the handle. Keyed on ``value``, the push after an edit finds
    nothing, adds a second sinkhole, and leaves the first one blocking a
    site nobody asked to block any more. Same reasoning and the same
    shape as :class:`NatRuleConfig`'s own ``vlan_id`` -- see
    ``mikrotik_adapter.configure_content_filter_rule``'s own docstring."""

    rule_id: str  # this rule's own stable id, and its device-side identity
    value_type: str  # "domain" | "ip_cidr"
    value: str  # a bare domain name ("facebook.com") or an IP/CIDR
    label: str  # human-readable label, carried in the device's own comment


@dataclass(frozen=True, slots=True)
class ProvisionResult:
    success: bool
    applied_content_summary: str | None
    error_message: str | None


@dataclass(frozen=True, slots=True)
class PingResult:
    """The real, parsed result of one ``/tool/ping`` execution -- ported
    from ``app.domains.isp.device_adapters.PingResult`` /
    ``app.domains.network_diagnostics.device_adapters.PingResult`` (both
    cloud-guest-repo call sites share an identical shape and identical
    RouterOS command; see ``mikrotik_adapter.py``'s ``ping`` docstring)."""

    sent: int
    received: int
    packet_loss_percentage: float
    avg_rtt_ms: float | None


@dataclass(frozen=True, slots=True)
class TracerouteHop:
    """One hop's own final, cumulative state from a ``/tool/traceroute``
    execution. ``address`` is ``None`` for a hop that never responded.
    Ported from
    ``app.domains.network_diagnostics.device_adapters.TracerouteHop``."""

    hop_number: int
    address: str | None
    packet_loss_percentage: float
    avg_rtt_ms: float | None


@dataclass(frozen=True, slots=True)
class TracerouteResult:
    """Ported from
    ``app.domains.network_diagnostics.device_adapters.TracerouteResult``."""

    hops: list[TracerouteHop] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class QueueDeviceStatus:
    """Real, current device-side queue counters a successful
    ``read_queue_status()`` call returns -- ported from
    ``app.domains.queue_management.device_adapters.QueueDeviceStatus``."""

    device_queue_id: str
    name: str | None
    target: str | None
    disabled: bool
    bytes_uploaded: int | None
    bytes_downloaded: int | None
    packets_uploaded: int | None
    packets_downloaded: int | None
    queued_bytes: int | None


@dataclass(frozen=True, slots=True)
class DeviceDiscoveryResult:
    """Real device facts a successful ``discover()`` call returns --
    ported from
    ``app.domains.provisioning_engine.device_adapters.DeviceDiscoveryResult``."""

    vendor: DeviceVendor
    model: str | None
    serial_number: str | None
    firmware_version: str | None
    cpu_load_percent: float | None
    free_memory_bytes: int | None
    total_memory_bytes: int | None
    uptime_seconds: int | None
    interfaces: list[str] = field(default_factory=list)
    mac_address: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceHealthResult:
    """Ported from
    ``app.domains.provisioning_engine.device_adapters.DeviceHealthResult``."""

    healthy: bool
    cpu_load_percent: float | None
    free_memory_bytes: int | None
    uptime_seconds: int | None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class SpeedTestResult:
    """The real, measured result of one on-demand WAN download-speed test --
    genuine bytes moved over the device's own real uplink in genuine wall-
    clock time, never an estimate. See ``mikrotik_adapter.py``'s
    ``run_speed_test`` docstring for exactly how this is measured (RouterOS
    ``/tool/fetch``) and its one real, documented precision caveat (whole-
    second duration granularity on this command).

    Upload throughput is deliberately not part of this shape: no vendor
    adapter in this package has a genuine way to measure real upload speed
    against the public internet yet (see that same docstring) -- a caller
    must never synthesize one to fill the gap."""

    download_mbps: float
    downloaded_bytes: int
    duration_seconds: float
    test_url: str


@dataclass(frozen=True, slots=True)
class RawCommandResult:
    """The real, unfiltered outcome of one raw SSH console command --
    ported from
    ``app.domains.provisioning_engine.device_adapters.RawCommandResult``.
    Unlike every other adapter method, a non-zero ``exit_status`` is not
    raised as an exception -- see that class's own docstring for why."""

    command: str
    stdout: str
    stderr: str
    exit_status: int


_DEFAULT_QUEUE_PRIORITY = 8  # ported from
# app.domains.queue_management.constants.DEFAULT_QUEUE_PRIORITY


@runtime_checkable
class DeviceGatewayAdapter(Protocol):
    """One Adapter per vendor. Every method mirrors a REAL operation this
    platform performs today (see PRD section 2.1) -- ported, not invented.
    A stubbed vendor may raise NotImplementedError from any method; the
    Protocol shape must still be fully implemented (or explicitly declared
    partial via `capabilities()`, see below) so callers can branch on
    capability rather than getting a surprise exception deep in a task."""

    vendor: DeviceVendor

    # -- discovery / telemetry (read-only) -----------------------------
    async def get_interface_list(self, creds: DeviceCredentials) -> list[InterfaceInfo]: ...

    async def read_network_snapshot(self, creds: DeviceCredentials) -> NetworkSnapshot:
        """Every interface and every ``/ip address`` on the device, read in
        one connection and filtered by nothing.

        Distinct from :meth:`get_interface_list`, which exists to back a
        *DHCP* picker and therefore drops every interface already carrying
        an ``/ip dhcp-server`` -- on a real router that removes ``bridge``,
        which is exactly the interface a VLAN trunk hangs off. A picker
        that cannot offer the trunk parent is not a VLAN picker.

        Read-only, and the single read a VLAN push preflight makes: whether
        the router answers at all, whether the named parent/port exists,
        and whether the subnet collides with one the device already carries
        are one question asked once, not three sessions that can disagree.
        """
        ...
    async def get_wan_health(self, creds: DeviceCredentials, *, target_ip: str) -> WanHealth: ...
    async def list_connected_devices(self, creds: DeviceCredentials) -> list[ConnectedDevice]: ...

    # -- lifecycle -------------------------------------------------------
    async def provision_device(
        self, creds: DeviceCredentials, *, rendered_config: str, content_type: str
    ) -> ProvisionResult:
        """`rendered_config` is vendor-specific config text/JSON already
        rendered by the caller (or, longer-term, by this adapter itself --
        see PRD section 9 Phase 3 note on renderer ownership). `content_type`
        mirrors router_provisioning.adapters' existing
        `build_job_payload`'s `content_type` field (e.g. "routeros_script")."""
        ...

    async def reboot_device(self, creds: DeviceCredentials) -> None: ...

    # -- network config push ---------------------------------------------
    async def configure_vlan(self, creds: DeviceCredentials, *, vlan: VlanConfig) -> None: ...

    async def configure_vlan_hotspot(
        self, creds: DeviceCredentials, *, hotspot: VlanHotspotConfig
    ) -> None:
        """Puts a captive portal on one VLAN's own interface.

        The six objects ``network_config.renderers._render_vlan_hotspot``
        renders, issued as real API operations: pool, DHCP server, DHCP
        network, hotspot profile, the static DNS record that makes the
        profile's ``dns-name`` resolve, and the hotspot server. Scoped to
        this VLAN's interface and named after its id, so it never disturbs
        the router's default ``hotspot1`` or another VLAN's portal.

        Idempotent, and *updating* where a field an operator can edit
        changed -- a re-push after re-subnetting a VLAN has to move the
        pool, not silently leave the old one.

        Callers must not point this and :meth:`configure_dhcp_pool` at the
        same interface: a portal brings its own ``/ip dhcp-server``, and
        RouterOS refuses a second one on an interface that already has
        one.
        """
        ...
    async def configure_dhcp_pool(self, creds: DeviceCredentials, *, pool: DhcpPoolConfig) -> None: ...

    async def configure_nat_masquerade(
        self, creds: DeviceCredentials, *, rule: NatRuleConfig
    ) -> None:
        """Gives one VLAN's subnet real internet access, by realizing a
        source-NAT masquerade rule for it on the device's own WAN-facing
        interface.

        A VLAN with an address and a DHCP pool is a working *local*
        network and nothing more: without this, its guests get a lease, a
        gateway, and no route off the router. This is the toggle that
        makes the difference.

        Idempotent, and idempotent on *identity* rather than on content:
        the rule is found again by a marker derived from ``rule.vlan_id``,
        so editing the VLAN's subnet updates the existing rule instead of
        leaving an orphan behind and adding a second one that masquerades
        a subnet nothing uses any more.
        """
        ...

    # -- network config teardown ------------------------------------------
    # Deleting a row never removed anything from the device: the platform
    # could create a VLAN or a pool on a router and then had no way to take
    # it back off, so a "deleted" object went on serving traffic forever.
    # Both are idempotent -- removing what is already absent is a no-op, not
    # an error, so a retry after a partial failure completes cleanly.
    async def delete_vlan(
        self, creds: DeviceCredentials, *, vlan: VlanConfig
    ) -> None: ...

    async def delete_vlan_hotspot(
        self, creds: DeviceCredentials, *, hotspot: VlanHotspotConfig
    ) -> None:
        """Takes one VLAN's captive portal back off the device.

        Removes the six objects in the reverse of the order they were
        created, because RouterOS enforces the references between them: the
        hotspot server holds the profile and the pool, and the DHCP server
        holds the pool. Idempotent.
        """
        ...

    async def delete_dhcp_pool(
        self, creds: DeviceCredentials, *, pool: DhcpPoolConfig
    ) -> None: ...

    async def delete_nat_masquerade(
        self, creds: DeviceCredentials, *, rule: NatRuleConfig
    ) -> None:
        """Takes one VLAN's internet access back off the device.

        The same call serves two different intents -- the operator turned
        the NAT toggle off, or deleted the VLAN outright -- because both
        mean the same thing on the device: this VLAN's masquerade rule
        must not be there. Only ``rule.vlan_id`` is consulted; a rule left
        over from an older subnet is still this VLAN's rule and is removed
        too.

        Idempotent: removing what is already absent is a no-op, not an
        error.
        """
        ...

    async def configure_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None: ...

    async def delete_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None:
        """Takes one port-forwarding rule back off the device.

        Only ``rule.rule_id`` is consulted, by the same comment identity
        :meth:`configure_port_forward` writes under -- so a rule left from
        an earlier external port or internal host is still this row's rule
        and is removed too. Matching on the current field values is exactly
        how one would be orphaned instead: still forwarding a public port,
        with nothing in this platform left pointing at it.

        Idempotent: removing what is already absent is a no-op, not an
        error.
        """
        ...

    async def set_radius_client_config(
        self, creds: DeviceCredentials, *, config: RadiusClientConfig
    ) -> None: ...

    async def configure_content_filter_rule(
        self, creds: DeviceCredentials, *, rule: ContentFilterRuleConfig
    ) -> None:
        """Realizes one content-filtering rule on the device -- a real
        DNS sinkhole (``rule.value_type == "domain"``) or address-list
        membership plus a shared enforcement DROP rule
        (``rule.value_type == "ip_cidr"``). See the MikroTik
        implementation's own docstring for the full, honest scope this
        deliberately does and does not cover (no Layer7, no web-proxy, no
        TLS interception -- ever).

        Idempotent on ``rule.rule_id``: re-realizing an unchanged rule adds
        nothing and raises nothing, and editing the blocked value updates
        the objects already carrying this rule's marker rather than adding
        a second set beside them."""
        ...

    async def configure_qos_packet_mark(
        self, creds: DeviceCredentials, *, rule: QosPacketMarkConfig
    ) -> None:
        """Realizes the ``/ip firewall mangle`` packet mark half of one QoS
        rule -- the half that decides which packets the paired
        ``/queue tree`` entry ever sees. Without it the queue is inert and
        the platform is claiming a prioritisation that is not happening.

        Idempotent on ``rule.rule_id``: re-realizing an unchanged rule
        writes nothing and raises nothing, and editing the match updates
        the rule already carrying this rule's marker rather than adding a
        second one beside it."""
        ...

    async def delete_qos_packet_mark(
        self, creds: DeviceCredentials, *, rule_id: str
    ) -> None:
        """Takes one QoS rule's mangle mark back off the device, by the
        same ``rule_id`` identity the write path stamps it with -- so a
        rule whose match was edited since the last push is still found and
        removed rather than left marking traffic for a rule the customer
        deleted.

        Idempotent: removing what is already absent is a no-op."""
        ...

    async def delete_content_filter_rule(
        self, creds: DeviceCredentials, *, rule: ContentFilterRuleConfig
    ) -> None:
        """Takes one content-filtering rule back off the device, by the
        same ``rule.rule_id`` identity the write path stamps it with -- so
        a rule whose blocked value was edited since the last push is still
        found and removed rather than orphaned.

        Idempotent: removing what is already absent is a no-op, so a retry
        after a partial failure completes cleanly."""
        ...

    # -- disconnect / kick -------------------------------------------------
    async def disconnect_device(
        self, creds: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None: ...

    # -- diagnostics (network_diagnostics + isp call sites share `ping`) --
    async def ping(
        self, creds: DeviceCredentials, *, target: str, count: int, timeout_seconds: int
    ) -> PingResult:
        """Issues ``count`` real ICMP echoes at ``target`` *from the
        device itself* and returns the parsed, cumulative result. Shared
        verbatim by both cloud-guest-repo's ``network_diagnostics`` and
        ``isp`` call sites -- same RouterOS ``/tool/ping`` command, same
        reply shape (PRD section 2.1, items 2 and 6)."""
        ...

    async def traceroute(
        self,
        creds: DeviceCredentials,
        *,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        """Issues a real traceroute *from the device itself* toward
        ``target``. Ported from
        ``app.domains.network_diagnostics.device_adapters``."""
        ...

    # -- isp-specific WAN link telemetry -----------------------------------
    async def get_active_default_gateway(self, creds: DeviceCredentials) -> str | None:
        """Real, live lookup of the router's own currently-usable
        ``0.0.0.0/0`` gateway for a DHCP-mode WAN link. Prefers a genuinely
        *dynamic* default route (RouterOS's own live DHCP-negotiated
        gateway); when none exists, falls back to any other default route
        that is currently *active* (not merely present -- RouterOS clears
        this the instant a ``check-gateway`` probe fails) and not
        disabled. ``None`` only if no usable default route exists at all
        either way. Renamed 2026-08-17 from ``get_dynamic_default_gateway``
        (dynamic-only, no fallback) after a confirmed fleet-wide production
        bug: this platform's own Setup Script generator deliberately
        provisions a *static* default route (``add-default-route=no`` on
        the dhcp-client, to avoid it fighting the routing-mark/failover
        mangle rules), so a router set up exactly as intended never has a
        dynamic default route to find, and every DHCP-mode link on it was
        permanently misreported as unavailable. Ported from
        ``app.domains.isp.device_adapters.get_active_default_gateway``."""
        ...

    async def get_pppoe_interface_status(
        self, creds: DeviceCredentials, *, interface_name: str
    ) -> bool:
        """Whether the named PPPoE client interface is really up right
        now. Ported from
        ``app.domains.isp.device_adapters.get_pppoe_interface_status``,
        including its stale-interface-name single-candidate fallback."""
        ...

    async def get_interface_traffic_counters(
        self, creds: DeviceCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        """Real, cumulative ``(rx_bytes, tx_bytes)`` counters for the
        named interface right now -- ``None`` if no interface with that
        name exists. Ported from
        ``app.domains.isp.device_adapters.get_interface_traffic_counters``."""
        ...

    async def run_speed_test(
        self, creds: DeviceCredentials, *, download_url: str
    ) -> SpeedTestResult:
        """Issues a real, on-demand download from ``download_url`` *from
        the device itself* (genuine traffic over its real WAN uplink, not
        this backend's own network path) and reports the genuine measured
        download throughput. ``download_url`` is fully caller-specified
        (which public test-file host and how many bytes to request is an
        ISP-domain business decision, not something this vendor-neutral
        contract should hardcode) -- exactly the same division of
        responsibility as ``ping``'s caller-specified ``target``.
        ``creds.timeout_seconds`` must be sized by the caller to
        genuinely accommodate the real download's expected duration (this
        is a slow, on-demand, multi-second-or-more real action, not a
        quick health-check read) -- see the MikroTik implementation's own
        docstring for real, measured timings against real hardware."""
        ...

    # -- queue management (QoS/bandwidth shaping) --------------------------
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
        priority: int = _DEFAULT_QUEUE_PRIORITY,
    ) -> str:
        """Creates a real ``/queue simple`` entry. Returns the device-side
        queue id. Ported from
        ``app.domains.queue_management.device_adapters.create_simple_queue``."""
        ...

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
        priority: int = _DEFAULT_QUEUE_PRIORITY,
    ) -> None:
        """Updates an existing ``/queue simple`` entry's rate/burst/
        priority fields."""
        ...

    async def delete_simple_queue(
        self, creds: DeviceCredentials, *, device_queue_id: str
    ) -> None:
        """Removes a ``/queue simple`` entry entirely."""
        ...

    async def create_queue_tree(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        parent: str,
        packet_mark: str | None,
        max_limit_kbps: int,
        priority: int = _DEFAULT_QUEUE_PRIORITY,
        queue_type_name: str | None = None,
    ) -> str:
        """Creates a real ``/queue tree`` entry. Returns the device-side
        queue id."""
        ...

    async def apply_pcq(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        rate_kbps: int,
        classifier: str = "dst-address",
    ) -> str:
        """Creates a real ``/queue type`` entry with ``kind=pcq``. Returns
        the device-side queue-type id."""
        ...

    async def set_priority(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        priority: int,
        queue_kind: str = "simple",
    ) -> None:
        """Updates only the ``priority`` field of an existing simple queue
        or queue-tree entry."""
        ...

    async def assign_queue_to_target(
        self, creds: DeviceCredentials, *, device_queue_id: str, target: str
    ) -> None:
        """Updates only the ``target`` field of an existing ``/queue
        simple`` entry."""
        ...

    async def remove_queue(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> None:
        """Removes a queue entry of either kind (``"simple"`` or
        ``"tree"``)."""
        ...

    async def read_queue_status(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> QueueDeviceStatus:
        """Reads real, current counters for one queue entry."""
        ...

    # -- provisioning engine (discovery/push/verify/health/backup/restore) -
    async def discover(self, creds: DeviceCredentials) -> DeviceDiscoveryResult:
        """Connects and returns real, current device facts. Ported from
        ``app.domains.provisioning_engine.device_adapters.discover``."""
        ...

    async def push_config(self, creds: DeviceCredentials, *, config_content: str) -> None:
        """Uploads and applies ``config_content`` to the device. Ported
        from
        ``app.domains.provisioning_engine.device_adapters.push_config``."""
        ...

    async def verify_config(
        self, creds: DeviceCredentials, *, expected_content: str
    ) -> bool:
        """Confirms the config actually applied matches
        ``expected_content``."""
        ...

    async def health_check(self, creds: DeviceCredentials) -> DeviceHealthResult:
        """A lighter-weight version of ``discover`` -- current load/uptime
        only."""
        ...

    async def backup(self, creds: DeviceCredentials) -> bytes:
        """Triggers a device-side backup and returns its raw bytes."""
        ...

    async def restore(self, creds: DeviceCredentials, *, backup_content: bytes) -> None:
        """Uploads ``backup_content`` and triggers a device-side restore
        from it."""
        ...

    async def upload_file(
        self, creds: DeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        """A generic file upload -- the primitive ``push_config``/
        ``restore`` are themselves built on."""
        ...

    async def execute_raw_command(
        self, creds: DeviceCredentials, *, command: str
    ) -> RawCommandResult:
        """Runs exactly ``command`` over the device's real SSH console
        connection, with no interpretation, whitelisting, or retry."""
        ...

    # -- capability introspection -----------------------------------------
    def capabilities(self) -> dict[str, bool]:
        """Which of the above this vendor's adapter genuinely implements
        today, e.g. {"get_wan_health": True, "configure_port_forward": False}.
        Mirrors router_provisioning.adapters.describe_capabilities's existing
        precedent. Callers (cloud-guest-repo) should check this before
        calling an operation on a non-MikroTik router in Phase 1/2, rather
        than catching NotImplementedError as control flow."""
        ...


__all__ = [
    "DeviceVendor",
    "UnsupportedVendorError",
    "DeviceCredentials",
    "InterfaceInfo",
    "IpAddressInfo",
    "NetworkSnapshot",
    "WanHealth",
    "ConnectedDevice",
    "VlanConfig",
    "VlanHotspotConfig",
    "DhcpPoolConfig",
    "NatRuleConfig",
    "PortForwardConfig",
    "RadiusClientConfig",
    "ContentFilterRuleConfig",
    "QosPacketMarkConfig",
    "ProvisionResult",
    "SpeedTestResult",
    "PingResult",
    "TracerouteHop",
    "TracerouteResult",
    "QueueDeviceStatus",
    "DeviceDiscoveryResult",
    "DeviceHealthResult",
    "RawCommandResult",
    "DeviceGatewayAdapter",
]

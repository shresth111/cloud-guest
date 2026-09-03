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

import asyncssh
import librouteros
from librouteros.exceptions import LibRouterosError

from .contract import (
    ConnectedDevice,
    ContentFilterRuleConfig,
    DeviceCredentials,
    DeviceDiscoveryResult,
    DeviceHealthResult,
    DeviceVendor,
    DhcpPoolConfig,
    InterfaceInfo,
    IpAddressInfo,
    NatRuleConfig,
    NetworkSnapshot,
    PingResult,
    PortForwardConfig,
    ProvisionResult,
    QueueDeviceStatus,
    RadiusClientConfig,
    RawCommandResult,
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
_CONTENT_FILTER_ADDRESS_LIST_NAME = "wyfyguest-content-filter-blocked"
_CONTENT_FILTER_ENFORCEMENT_COMMENT = (
    "Wyfy Guest content filtering: block listed addresses"
)
# NAT / internet access: the marker that makes one VLAN's masquerade rule
# findable again on the next push. It is deliberately the rule's *identity*
# rather than any of its RouterOS fields -- ``src-address`` is exactly what
# an operator edits, so keying on it would leave the old rule behind and add
# a second one. See ``configure_nat_masquerade``'s own docstring.
_NAT_RULE_COMMENT_PREFIX = "WyfyGuest VLAN "


def _nat_rule_comment(vlan_id: int) -> str:
    return f"{_NAT_RULE_COMMENT_PREFIX}{vlan_id}"


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
                )
            )
        return NetworkSnapshot(
            interfaces=listed,
            ip_addresses=[
                IpAddressInfo(
                    address=str(row["address"]),
                    interface=str(row["interface"]) if row.get("interface") else None,
                    disabled=_is_truthy(row.get("disabled", False)),
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

        The address is removed. The port is **not** put back into a bridge:
        which bridge it belonged to was never recorded, and re-adding it to
        a guessed one would silently rejoin a port to the wrong L2 segment.
        The port is left out of every bridge, holding no address -- inert
        and safe, and visible to an operator as an unbridged port.
        """
        self._remove_ip_address(api, vlan.ip_cidr, vlan.interface)

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
        }
        menu = api.path("ip", "hotspot", "profile")
        for row in menu:
            if row.get("name") != name:
                continue
            changed = {
                key: value for key, value in desired.items() if row.get(key) != value
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
                self._remove_where(
                    api, ("ip", "dhcp-server", "network"), "address", network
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
                self._remove_where(
                    api, ("ip", "dhcp-server", "network"), "address", network
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
                self._ensure_dhcp_network(api, str(network), network_fields)
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
                    if row.get(key) != value
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
        self, api, address: str, fields: dict[str, str]
    ) -> None:
        """Creates the ``/ip dhcp-server network`` row for this subnet, or
        updates the existing row for that exact address.

        Keyed on ``address`` because that is what RouterOS itself treats as
        the row's identity here -- adding a second row for the same subnet
        is what produces "already have such item".
        """
        for row in api.path("ip", "dhcp-server", "network"):
            if row.get("address") == address:
                changed = {
                    key: value
                    for key, value in fields.items()
                    if row.get(key) != value
                }
                if changed:
                    api.path("ip", "dhcp-server", "network").update(
                        **{".id": row[".id"], **changed}
                    )
                return
        api.path("ip", "dhcp-server", "network").add(**fields)

    async def configure_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None:
        """Ported from
        ``network_config/renderers.py::render_port_forwarding_rule`` --
        same real ``/ip firewall nat add chain=dstnat ... action=dst-nat``
        operation, issued directly over the structured API."""
        await asyncio.to_thread(self._configure_port_forward_sync, creds, rule)

    def _configure_port_forward_sync(
        self, creds: DeviceCredentials, rule: PortForwardConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                fields: dict[str, str] = {
                    "chain": "dstnat",
                    "protocol": rule.protocol,
                    "action": "dst-nat",
                    "to-addresses": rule.internal_ip,
                    "to-ports": str(rule.internal_port),
                }
                fields["dst-port"] = str(rule.external_port)
                api.path("ip", "firewall", "nat").add(**fields)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_port_forward: {exc}"
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
        ``src-address`` (the original's WireGuard-tunnel-IP field) is
        intentionally not part of this vendor-agnostic port."""
        await asyncio.to_thread(self._set_radius_client_config_sync, creds, config)

    def _set_radius_client_config_sync(
        self, creds: DeviceCredentials, config: RadiusClientConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                api.path("radius").add(
                    service="hotspot",
                    address=config.radius_server_host,
                    secret=config.radius_secret,
                    **{
                        "authentication-port": str(config.auth_port),
                        "accounting-port": str(config.acct_port),
                    },
                )
                api.path("radius", "incoming").update(accept="yes", port="3799")
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"set_radius_client_config: {exc}"
                ) from exc
        finally:
            api.close()

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
        this ports; that same reasoning applies here unchanged."""
        await asyncio.to_thread(self._configure_content_filter_rule_sync, creds, rule)

    def _configure_content_filter_rule_sync(
        self, creds: DeviceCredentials, rule: ContentFilterRuleConfig
    ) -> None:
        api = self._connect_api(creds)
        try:
            try:
                if rule.value_type == "ip_cidr":
                    api.path("ip", "firewall", "address-list").add(
                        list=_CONTENT_FILTER_ADDRESS_LIST_NAME,
                        address=rule.value,
                        comment=rule.label,
                    )
                    self._ensure_content_filter_enforcement_rule(api)
                else:
                    domain = rule.value
                    api.path("ip", "dns", "static").add(
                        name=domain,
                        type="A",
                        address=_CONTENT_FILTER_SINKHOLE_ADDRESS,
                        comment=rule.label,
                    )
                    api.path("ip", "dns", "static").add(
                        regexp=_domain_subdomain_regex(domain),
                        type="A",
                        address=_CONTENT_FILTER_SINKHOLE_ADDRESS,
                        comment=f"{rule.label} (subdomains)",
                    )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_content_filter_rule: {exc}"
                ) from exc
        finally:
            api.close()

    def _ensure_content_filter_enforcement_rule(self, api) -> None:  # noqa: ANN001
        """Real read-before-write dedup for the one, router-global
        ``/ip firewall filter`` DROP rule every ``ip_cidr``-type content
        filter rule relies on -- see
        ``configure_content_filter_rule``'s own docstring for why this
        must exist exactly once, not once per rule."""
        existing_filters = list(api.path("ip", "firewall", "filter"))
        already_present = any(
            row.get("comment") == _CONTENT_FILTER_ENFORCEMENT_COMMENT
            for row in existing_filters
        )
        if not already_present:
            api.path("ip", "firewall", "filter").add(
                chain="forward",
                **{"dst-address-list": _CONTENT_FILTER_ADDRESS_LIST_NAME},
                action="drop",
                comment=_CONTENT_FILTER_ENFORCEMENT_COMMENT,
            )

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
            self._queue_add_sync, creds, ("queue", "tree"), fields, "create_queue_tree"
        )

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

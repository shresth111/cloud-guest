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
import ipaddress
import logging
import re

import librouteros
from librouteros.exceptions import LibRouterosError

from .contract import (
    ConnectedDevice,
    DeviceCredentials,
    DeviceVendor,
    DhcpPoolConfig,
    InterfaceInfo,
    PortForwardConfig,
    ProvisionResult,
    RadiusClientConfig,
    VlanConfig,
    WanHealth,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_SSH_PORT = 22
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
            raise MikroTikDeviceError(creds.host, str(exc)) from exc

    def _ssh_port(self, creds: DeviceCredentials) -> int:
        return _safe_int(creds.extra.get("ssh_port"), default=_DEFAULT_SSH_PORT) or (
            _DEFAULT_SSH_PORT
        )

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
                raise MikroTikDeviceError(creds.host, str(exc)) from exc
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
                )
            )
        return result

    async def get_wan_health(self, creds: DeviceCredentials, *, target_ip: str) -> WanHealth:
        """Composes three real, independently-audited read operations from
        ``isp/device_adapters.py`` into the one vendor-agnostic
        ``WanHealth`` shape:

        * ``ping`` (``/tool/ping``) -> ``reachable``/``latency_ms``/
          ``packet_loss_percent``.
        * ``get_dynamic_default_gateway`` (``/ip/route``, never filtered by
          interface name -- see that module's own docstring) ->
          ``dynamic_gateway``, and incidentally the WAN-facing interface
          name RouterOS itself associates with that route.
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

        dynamic_gateway: str | None = None
        wan_interface: str | None = None
        for row in route_rows:
            if (
                row.get("dst-address") == "0.0.0.0/0"
                and str(row.get("dynamic", "false")).lower() == "true"
            ):
                gateway = row.get("gateway")
                dynamic_gateway = str(gateway) if gateway else None
                iface = row.get("interface")
                wan_interface = str(iface) if iface else None
                break

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
        api = self._connect_api(creds)
        try:
            try:
                wireless_menu = api.path("interface", "wireless", "registration-table")
                for row in wireless_menu:
                    if normalize_mac_address(row.get("mac-address")) == mac_address:
                        wireless_menu.remove(row.get(".id"))
                        break
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
                error_message=str(exc),
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
        vlan_interface = f"vlan{vlan.vlan_id}"
        api = self._connect_api(creds)
        try:
            try:
                api.path("interface", "vlan").add(
                    name=vlan_interface,
                    **{"vlan-id": str(vlan.vlan_id)},
                    interface=vlan.interface,
                    comment=vlan.name,
                )
                if vlan.ip_cidr:
                    api.path("ip", "address").add(
                        address=vlan.ip_cidr, interface=vlan_interface
                    )
            except LibRouterosError as exc:
                raise MikroTikDeviceError(creds.host, f"configure_vlan: {exc}") from exc
        finally:
            api.close()

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
        network = _smallest_enclosing_network(pool.range_start, pool.range_end)
        api = self._connect_api(creds)
        try:
            try:
                api.path("ip", "pool").add(
                    name=f"{identifier}-pool",
                    ranges=f"{pool.range_start}-{pool.range_end}",
                )
                api.path("ip", "dhcp-server").add(
                    name=f"{identifier}-dhcp",
                    interface=pool.interface,
                    **{
                        "address-pool": f"{identifier}-pool",
                        "lease-time": f"{pool.lease_time_seconds}s",
                    },
                    disabled="no",
                )
                network_fields: dict[str, str] = {"address": str(network)}
                if pool.gateway:
                    network_fields["gateway"] = pool.gateway
                if pool.dns_servers:
                    network_fields["dns-server"] = ",".join(pool.dns_servers)
                api.path("ip", "dhcp-server", "network").add(**network_fields)
            except LibRouterosError as exc:
                raise MikroTikDeviceError(
                    creds.host, f"configure_dhcp_pool: {exc}"
                ) from exc
        finally:
            api.close()

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
            "configure_dhcp_pool": True,
            "configure_port_forward": True,
            "set_radius_client_config": True,
            "disconnect_device": True,
        }


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


__all__ = ["MikroTikAdapter", "MikroTikDeviceError", "normalize_mac_address"]

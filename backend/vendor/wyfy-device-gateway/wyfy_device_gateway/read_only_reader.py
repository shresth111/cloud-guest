"""``ReadOnlyDeviceReader`` -- a discovery-only RouterOS reader that is
read-only **by construction**, not by convention.

Why this class exists (router-fleet redesign, spec P1 / plan D1): the full
:class:`~.mikrotik_adapter.MikroTikAdapter` that serves discovery today also
exposes ``push_config``, ``restore``, ``upload_file`` and an un-whitelisted
``execute_raw_command`` -- the same object, the same credentials, the full
write surface. Safe discovery must not merely *promise* not to write; the
object handed to discovery code must be structurally incapable of writing.

Three layers of enforcement, in order of strength:

1. **Surface**: this class exposes exactly three public operations --
   ``read_section``, ``read_all`` and the introspective ``section_names``.
   There is no ``push_config``, no ``restore``, no ``execute_raw_command``,
   no ``upload_file``, no SSH transport of any kind on this type (it never
   imports or opens ``asyncssh``); a write cannot even be *expressed*
   against it. Discovery service code is typed against this class, so the
   type checker rejects a write at the call site.
2. **Allowlist**: every RouterOS API sentence this class ever sends is a
   print-style read of a path drawn from the frozen
   :data:`READ_ONLY_SECTION_PATHS` map, re-validated against
   :data:`_ALLOWED_PATH_SEGMENTS` immediately before any socket I/O --
   an unknown section (or a corrupted map) raises
   :class:`ReadOnlyViolationError` before a connection is even used. The
   ``librouteros`` ``Path`` object is only ever *iterated* (which issues
   ``/.../print`` on the wire); its ``.add``/``.update``/``.remove``
   mutators are never invoked, and the raw ``api("<command>")`` calling
   form is never used at all.
3. **Row sanitization**: RouterOS ``print`` replies can carry secrets
   (``/interface/wireguard`` returns ``private-key``,
   ``/interface/pppoe-client`` returns ``password``, ``/radius`` returns
   ``secret``, and the platform's own heartbeat scheduler embeds the agent
   credential in its ``on-event`` fetch URL). Spec safety rule 11 ("never
   expose passwords, API tokens, WireGuard private keys, RADIUS secrets")
   is applied *here*, at the transport boundary: every sanitized field is
   stripped from the row before it leaves this module and replaced with a
   ``has_<field>`` presence boolean, so no caller above this line ever
   holds the secret material at all.

Same honesty posture as the rest of this package: real client code, never
exercised against a live device in this sandbox -- the parsing/guard logic
is tested against the fake transport in ``tests/fake_transport.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

import librouteros
from librouteros.exceptions import LibRouterosError

from .contract import DeviceCredentials
from .mikrotik_adapter import (
    MikroTikConnectionError,
    _DEFAULT_API_PORT,
    _describe_exception,
)


class ReadOnlyViolationError(Exception):
    """A read was requested for a path outside the frozen read-only
    allowlist. Raised *before* any socket I/O -- this is the defense-in-
    depth guard of layer 2 in the module docstring, and hitting it means a
    programming error (or tampering), never a device-side condition."""

    def __init__(self, section: str) -> None:
        self.section = section
        super().__init__(
            f"section {section!r} is not in the read-only discovery allowlist"
        )


# The complete discovery read-set (spec P1 A-F). Every entry is a RouterOS
# menu path whose iteration issues a plain `/.../print` -- reads only.
# MappingProxyType + tuples: immutable at runtime, not just by convention.
READ_ONLY_SECTION_PATHS: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    {
        # A. system
        "system_resource": ("system", "resource"),
        "system_routerboard": ("system", "routerboard"),
        "system_identity": ("system", "identity"),
        "system_clock": ("system", "clock"),
        "system_ntp_client": ("system", "ntp", "client"),
        "system_packages": ("system", "package"),
        "system_schedulers": ("system", "scheduler"),
        # B. interfaces (dynamic -- never assume etherN)
        "interfaces": ("interface",),
        "interface_lists": ("interface", "list"),
        "interface_list_members": ("interface", "list", "member"),
        "vlan_interfaces": ("interface", "vlan"),
        # C. bridges
        "bridges": ("interface", "bridge"),
        "bridge_ports": ("interface", "bridge", "port"),
        "bridge_vlans": ("interface", "bridge", "vlan"),
        # D. WAN state
        "pppoe_clients": ("interface", "pppoe-client"),
        "ip_addresses": ("ip", "address"),
        "dhcp_clients": ("ip", "dhcp-client"),
        "routes": ("ip", "route"),
        "routing_tables": ("routing", "table"),
        # E. DNS
        "dns": ("ip", "dns"),
        # F. services
        "dhcp_servers": ("ip", "dhcp-server"),
        "dhcp_server_networks": ("ip", "dhcp-server", "network"),
        "ip_pools": ("ip", "pool"),
        "ip_services": ("ip", "service"),
        "firewall_filter": ("ip", "firewall", "filter"),
        "firewall_nat": ("ip", "firewall", "nat"),
        "firewall_mangle": ("ip", "firewall", "mangle"),
        "hotspot_servers": ("ip", "hotspot"),
        "hotspot_profiles": ("ip", "hotspot", "profile"),
        "hotspot_walled_garden": ("ip", "hotspot", "walled-garden"),
        "radius": ("radius",),
        "wireguard_interfaces": ("interface", "wireguard"),
        "wireguard_peers": ("interface", "wireguard", "peers"),
        "netwatch": ("tool", "netwatch"),
        # G. venue diagnostics
        #
        # Four reads added for the Connection Tools redesign. Each is a
        # plain `print`, each is confirmed working over port 8728 against
        # the lab hEX lite (RouterOS 7.23.3) by a script in
        # `backend/ops/probes/`, and each answers a venue question the
        # platform currently has to guess at. Not yet exposed on any
        # customer-facing route -- that is the product design. This is the
        # safe substrate underneath it.
        #
        # `hotspot_hosts` is the difference between "the guest is stuck on
        # the login page" and "the guest never reached the network".  A
        # device in `/ip/hotspot/host` with `authorized=no` has an
        # address and has been redirected to the portal and has not
        # logged in; a device absent from it is not on the network at
        # all. Today both look identical from the dashboard. Carries
        # guest MACs -- see the PII note below.
        # Confirmed by ops/probes/read_router_log.py.
        "hotspot_hosts": ("ip", "hotspot", "host"),
        # `bridge_hosts` is the closest this hardware gets to seeing
        # Wi-Fi. The routers have no radio, but the bridge's learned-MAC
        # table maps every MAC to the physical port it arrived on, so on a
        # multi-AP venue it identifies *which access point* a guest is
        # behind, and whether an AP is still present on its port at all.
        # It needs neither an IP (unlike `/ip/arp`) nor LLDP (unlike
        # `/ip/neighbor`) -- one frame is enough.
        # Confirmed by ops/probes/read_bridge_hosts.py.
        "bridge_hosts": ("interface", "bridge", "host"),
        # `neighbors` names the hardware plugged into each port -- an
        # LLDP/MNDP/CDP neighbour reports identity, platform and board.
        # Expect it to be EMPTY more often than not: the venue APs in the
        # field are TP-Link units in dumb-AP mode that advertise nothing,
        # and this was confirmed on the lab router with discovery enabled
        # on the port (ops/probes/hunt_ap_via_discovery.py). Treat a hit
        # as a bonus, never as the topology.
        # Confirmed by ops/probes/read_neighbours.py.
        "neighbors": ("ip", "neighbor"),
        # `dns_cache` distinguishes "DNS is broken" from "DNS is working
        # and returning an answer the customer does not like" -- including
        # this platform's own content-filter `/ip dns static` overrides,
        # which resolve blocked domains to the portal address. It is the
        # single most common cause of "one website will not open".
        #
        # COST WARNING, and it is the only one in this map: a busy venue
        # router can hold thousands of cache entries, and `read_all()`
        # pulls every row of every section. Callers that want this should
        # use `read_section("dns_cache")` and filter, or accept a large
        # reply. Do not add it to a high-frequency sweep unthinkingly.
        "dns_cache": ("ip", "dns", "cache"),
    }
)

# WHAT IS DELIBERATELY ABSENT FROM THIS MAP, AND WHY
#
# This allowlist is the substrate a customer-facing diagnostics page will
# be built on, so the omissions matter as much as the entries. Two
# RouterOS tools get asked for by name and must not be added here:
#
# `/tool/bandwidth-test` -- NEVER. Not here, not on any customer path,
# not behind a confirmation. It saturates the venue's uplink by design
# (that is the measurement), and on this hardware the traffic goes
# through a single 850MHz MIPS core rather than the switch chip, so it
# degrades DNS, DHCP and the captive portal simultaneously and keeps
# misbehaving after the test ends. Running it at a cafe at 8pm drops
# every guest, and any POS terminal sharing that uplink. It also cannot
# do the job: it requires a RouterOS BTest server on the far end and
# cannot measure throughput to the general internet -- confirmed against
# a real 7.16.2 hEX lite, which answered `{"detail":"no such command"}`.
# `MikroTikAdapter.run_speed_test` (`/tool/fetch`) is the real
# measurement and is already implemented and validated on hardware.
#
# `/tool/torch` -- not here, and not anywhere without a server-enforced
# duration. Torch is the only way to get live per-host *rate*, but it
# inspects every packet on the interface in software, which is a real
# CPU cost on this hardware while guests are using it. Worse, WITHOUT AN
# EXPLICIT `duration` IT STREAMS FOREVER: the librouteros generator
# blocks indefinitely and pins an open API connection to a production
# router, with no clean cancel in the calling style this package uses. A
# duration must be clamped server-side and never taken from a client
# field. It is also a privacy exposure -- it reveals identifiable
# guests' destination addresses and ports to a venue owner -- so any
# eventual use must aggregate to "device X used Y Mbps". Note that this
# class could not host torch anyway: it only ever *iterates* a `Path`
# (issuing `/.../print`), and torch is not a print.
#
# The safe answer to "who is using all the bandwidth" is
# `/ip/hotspot/active`'s own per-session `bytes-in`/`bytes-out`
# counters -- free, already read elsewhere in this package, and carrying
# no such hazards.
#
# PII, which sanitization here does NOT cover: `SANITIZED_ROW_FIELDS`
# below strips secret material (passwords, keys, RADIUS secrets). It does
# not strip guest personal data, and `hotspot_hosts` rows carry guest MAC
# addresses. That is a real and separate filtering problem which belongs
# to whatever renders these rows, not to this transport. Do not read the
# absence of a sanitizer as evidence the rows are safe to display.

_ALLOWED_PATH_SEGMENTS: frozenset[tuple[str, ...]] = frozenset(
    READ_ONLY_SECTION_PATHS.values()
)

# Fields whose values are secret material (or embed it) in a RouterOS print
# reply -- stripped at this boundary and replaced by a `has_<field>`
# presence boolean. See module docstring layer 3 for the concrete sources.
SANITIZED_ROW_FIELDS: frozenset[str] = frozenset(
    {
        "password",  # /interface/pppoe-client
        "private-key",  # /interface/wireguard
        "public-key",  # kept OUT of this set deliberately -- public keys
        # are not secrets and are useful for peer matching; listed here in
        # comment form only so nobody "helpfully" adds it later without
        # reading this.
        "secret",  # /radius
        "preshared-key",  # /interface/wireguard/peers
        "pre-shared-key",
        "passphrase",
        "wpa-passphrase",
        "wpa2-pre-shared-key",
        "on-event",  # /system/scheduler -- the platform's own heartbeat
        # scheduler embeds the router's agent credential in its fetch URL.
    }
) - {"public-key"}


def _sanitize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Strips secret-bearing fields, recording presence booleans instead.

    ``has_password: True`` tells the collector "PPPoE credentials exist on
    the device" (which discovery genuinely needs, spec P2's
    ``has_pppoe_credentials``) without the password ever leaving the
    transport layer."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key in SANITIZED_ROW_FIELDS:
            out[f"has_{key.replace('-', '_')}"] = bool(value)
        else:
            out[key] = value
    return out


@dataclass(frozen=True, slots=True)
class ReadOnlyStateCapture:
    """The raw result of one full read-only sweep: sanitized rows per
    section, plus per-section read errors (a missing package/menu on the
    device must degrade that one section, never fail the whole sweep)."""

    sections: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


class ReadOnlyDeviceReader:
    """See module docstring. Public surface is deliberately exactly three
    methods -- ``section_names`` / ``read_section`` / ``read_all`` -- and
    tests assert that surface never grows a mutating member."""

    def __init__(
        self,
        creds: DeviceCredentials,
        *,
        connect_fn: Callable[..., Any] | None = None,
    ) -> None:
        # Leading underscores: none of this state is public surface.
        self._creds = creds
        # Injection seam for the fake transport in tests; defaults to the
        # same real librouteros.connect the full adapter uses.
        self._connect_fn = connect_fn or librouteros.connect

    @classmethod
    def section_names(cls) -> tuple[str, ...]:
        return tuple(READ_ONLY_SECTION_PATHS)

    async def read_section(self, section: str) -> list[dict[str, Any]]:
        """Reads one allowlisted section; raises
        :class:`ReadOnlyViolationError` for anything not in the allowlist
        and :class:`~.mikrotik_adapter.MikroTikConnectionError` when the
        device cannot be reached. A device-side menu error (e.g. package
        not installed) propagates as ``LibRouterosError`` --
        :meth:`read_all` instead captures those into ``errors`` so a
        missing package never aborts the whole sweep."""
        capture = await asyncio.to_thread(self._read_sync, (section,), False)
        return capture.sections[section]

    async def read_all(
        self, sections: Sequence[str] | None = None
    ) -> ReadOnlyStateCapture:
        """One connection, the full (or given) read-set, per-section error
        capture. The default sweep is the entire spec-P1 read-set."""
        names = tuple(sections) if sections is not None else self.section_names()
        return await asyncio.to_thread(self._read_sync, names, True)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _read_sync(
        self, names: tuple[str, ...], capture_errors: bool
    ) -> ReadOnlyStateCapture:
        # Validate every requested section BEFORE opening any connection --
        # a single bad name aborts the whole sweep with zero I/O.
        segments_by_name: dict[str, tuple[str, ...]] = {}
        for name in names:
            segments = READ_ONLY_SECTION_PATHS.get(name)
            if segments is None or segments not in _ALLOWED_PATH_SEGMENTS:
                raise ReadOnlyViolationError(name)
            segments_by_name[name] = segments

        try:
            api = self._connect_fn(
                host=self._creds.host,
                username=self._creds.username,
                password=self._creds.secret,
                port=self._creds.port or _DEFAULT_API_PORT,
                timeout=self._creds.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise MikroTikConnectionError(
                self._creds.host, _describe_exception(exc)
            ) from exc

        capture = ReadOnlyStateCapture()
        try:
            for name, segments in segments_by_name.items():
                try:
                    # Iteration of a librouteros Path issues `/.../print` on
                    # the wire -- the only sentence this class ever sends.
                    rows = [dict(row) for row in api.path(*segments)]
                except LibRouterosError as exc:
                    if not capture_errors:
                        # Single-section callers (read_section) want the
                        # device-side error to propagate as-is -- see that
                        # method's docstring.
                        raise
                    capture.errors[name] = _describe_exception(exc)
                    continue
                capture.sections[name] = [_sanitize_row(row) for row in rows]
        finally:
            api.close()
        return capture


__all__ = [
    "READ_ONLY_SECTION_PATHS",
    "SANITIZED_ROW_FIELDS",
    "ReadOnlyDeviceReader",
    "ReadOnlyStateCapture",
    "ReadOnlyViolationError",
]

"""The single source of the desired ``/ip traffic-flow`` state.

Two config paths consume this module and nothing else defines the rows:

* the script generator -- :func:`render_traffic_flow_lines`, called from
  ``network_config.renderers.render_network_config``;
* the device writer -- :func:`desired_config` handed to
  ``MikroTikAdapter.apply_traffic_flow``, which writes and reads back.

The frontend paste script deliberately does NOT emit traffic-flow (it is
flag-gated and Master-only); the Master page shows these rendered lines
instead of keeping a third copy in TypeScript. ``test_traffic_flow_parity``
parses the rendered lines back and asserts they equal :func:`desired_config`.

Values and why (DESIGN.md §2):

* ``active-flow-timeout=1m`` -- the default 30m exports a long stream once,
  half an hour late, into the wrong 5-minute window.
* ``interfaces=all`` -- accounting happens per chain, so a forwarded packet
  is counted once, not once per interface.
* ``nat-src-address``/``nat-src-port`` -- not used by the MVP rollup; enabled
  now because changing the IPFIX field set later re-templates every exporter,
  and the NAT archive (DESIGN.md §6) needs them.
* the target's ``src-address`` is the router's tunnel address -- the hub maps
  an exporter to a router by exactly that address.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from wyfy_device_gateway.mikrotik_traffic_flow import TrafficFlowConfig

from app.domains.wireguard.validators import hub_reserved_ip

from .constants import TRAFFIC_FLOW_SECTION_HEADER, TRAFFIC_FLOW_TARGET_MARKER

__all__ = [
    "TrafficFlowTarget",
    "desired_config",
    "disabled_config",
    "render_traffic_flow_lines",
    "routeros_major_version",
    "traffic_flow_lines_for_router",
    "traffic_flow_target_for",
]

_SETTINGS: dict[str, str] = {
    "enabled": "yes",
    "interfaces": "all",
    "cache-entries": "4k",
    "active-flow-timeout": "1m",
    "inactive-flow-timeout": "15s",
    "packet-sampling": "no",
}

_IPFIX: dict[str, str] = {
    "nat-src-address": "yes",
    "nat-src-port": "yes",
}


@dataclass(frozen=True, slots=True)
class TrafficFlowTarget:
    """Where one router exports to, and from which address.

    ``collector_address`` is the hub's tunnel address (``hub_reserved_ip``),
    ``source_address`` the router's own tunnel address (its WireGuard peer)."""

    collector_address: str
    collector_port: int
    source_address: str


def desired_config(target: TrafficFlowTarget) -> TrafficFlowConfig:
    """Export ON, to ``target``."""
    return TrafficFlowConfig(
        settings=dict(_SETTINGS),
        ipfix=dict(_IPFIX),
        target={
            "dst-address": target.collector_address,
            "port": str(target.collector_port),
            "version": "ipfix",
            "src-address": target.source_address,
        },
        marker=TRAFFIC_FLOW_TARGET_MARKER,
    )


def disabled_config() -> TrafficFlowConfig:
    """Export OFF and our target removed. IPFIX field toggles are left as
    they are: they do nothing while export is off."""
    return TrafficFlowConfig(
        settings={"enabled": "no"},
        ipfix={},
        target=None,
        marker=TRAFFIC_FLOW_TARGET_MARKER,
    )


def routeros_major_version(version: str | None) -> int | None:
    if not version:
        return None
    head = version.strip().split(".", 1)[0]
    return int(head) if head.isdigit() else None


def _fields(fields: dict[str, str]) -> str:
    return " ".join(f"{key}={value}" for key, value in fields.items())


def render_traffic_flow_lines(
    config: TrafficFlowConfig, *, routeros_version: str | None
) -> list[str]:
    """RouterOS script lines for ``config`` (export ON only). Each line is
    one command so ``_idempotent_lines`` can wrap it.

    ``target add`` has no unique key and duplicates on every push -- two
    targets double-count every flow -- so it is guarded by a find on the
    marker, followed by a ``set`` that converges an existing row and a
    one-line removal of any extra marked rows. The two singleton ``set``s are
    idempotent by nature. The target goes in before export is switched on,
    the same order the device writer uses.

    RouterOS 6 spells the target differently and lacks ``src-address``; a
    router not positively known to run 7 gets a comment, not a guess."""
    major = routeros_major_version(routeros_version)
    if major != 7:
        return [
            TRAFFIC_FLOW_SECTION_HEADER,
            "# traffic-flow skipped: RouterOS 7 required "
            f"(router reports {routeros_version or 'no version'})",
        ]
    if config.target is None:
        raise ValueError("render_traffic_flow_lines renders export ON only")
    marker = config.marker
    find = f'[/ip traffic-flow target find where comment="{marker}"]'
    target = _fields(dict(config.target))
    return [
        TRAFFIC_FLOW_SECTION_HEADER,
        f":if ([:len {find}] = 0) do={{/ip traffic-flow target add {target} "
        f'comment="{marker}"}}',
        f"/ip traffic-flow target set {find} {target}",
        f":local wyfyTf {find}; :if ([:len $wyfyTf] > 1) do={{"
        "/ip traffic-flow target remove [:pick $wyfyTf 1 [:len $wyfyTf]]}",
        f"/ip traffic-flow ipfix set {_fields(dict(config.ipfix))}",
        f"/ip traffic-flow set {_fields(dict(config.settings))}",
    ]


class _Peer(Protocol):
    tunnel_ip_address: str


class _Server(Protocol):
    tunnel_network_cidr: str


def traffic_flow_target_for(
    peer: _Peer | None, server: _Server | None, settings: Any
) -> TrafficFlowTarget | None:
    """The export target for a router, or None when it has no tunnel (the
    collector is only reachable through it)."""
    if peer is None or server is None:
        return None
    return TrafficFlowTarget(
        collector_address=hub_reserved_ip(server.tunnel_network_cidr),
        collector_port=int(settings.traffic_flow_collector_port),
        source_address=peer.tunnel_ip_address,
    )


def traffic_flow_lines_for_router(
    *,
    router_id: Any,
    vendor: str | None,
    routeros_version: str | None,
    peer: _Peer | None,
    server: _Server | None,
    settings: Any,
) -> list[str] | None:
    """What ``render_network_config`` should carry for this router, or
    ``None`` for "no traffic-flow section". The generator-side gate: flag on,
    router allowlisted, MikroTik, and a tunnel to export over. The device
    writer applies the same gates in ``TrafficFlowDeviceService``."""
    if not settings.traffic_flow_enabled:
        return None
    if router_id not in settings.traffic_flow_router_id_set:
        return None
    if (vendor or "mikrotik").lower() != "mikrotik":
        return None
    target = traffic_flow_target_for(peer, server, settings)
    if target is None:
        return None
    return render_traffic_flow_lines(
        desired_config(target), routeros_version=routeros_version
    )

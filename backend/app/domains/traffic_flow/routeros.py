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
* ``cache-entries`` -- one constant (``ROUTEROS_CACHE_ENTRIES``); RouterOS's
  own default depends on the board, and the smallest value overflows early.
* the target row carries NO ``comment``: ``/ip traffic-flow target`` has no
  such property (RouterOS 7.21.4 answers "unknown parameter comment"). Our
  row is identified by its own ``dst-address`` + ``port`` -- the platform's
  collector -- in the writer and in every script line below alike.
* the target's ``src-address`` is the router's tunnel address -- the hub maps
  an exporter to a router by exactly that address.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from wyfy_device_gateway.mikrotik_traffic_flow import TrafficFlowConfig

from app.domains.wireguard.validators import hub_reserved_ip

from .constants import ROUTEROS_CACHE_ENTRIES, TRAFFIC_FLOW_SECTION_HEADER

__all__ = [
    "TrafficFlowTarget",
    "desired_config",
    "nat_events_on",
    "disabled_config",
    "TARGET_IDENTITY_FIELDS",
    "render_removal_lines",
    "render_traffic_flow_lines",
    "routeros_major_version",
    "target_identity",
    "traffic_flow_lines_for_router",
    "traffic_flow_target_for",
]

_SETTINGS: dict[str, str] = {
    "enabled": "yes",
    "interfaces": "all",
    "cache-entries": ROUTEROS_CACHE_ENTRIES,
    "active-flow-timeout": "1m",
    "inactive-flow-timeout": "15s",
    "packet-sampling": "no",
}

_IPFIX: dict[str, str] = {
    "nat-src-address": "yes",
    "nat-src-port": "yes",
}
#: IPFIX NAT event export (template 260) for the IPDR's Translated IP/Port.
#: Gated by ``traffic_flow_ipfix_nat_events`` (default false) and applied
#: nowhere until measured on a lab router (~/wyfy-ops/ipdr/NAT-RESEARCH.md
#: section 6). Turning it on re-templates every exporter.
_IPFIX_NAT_EVENTS: dict[str, str] = {
    "nat-dst-address": "yes",
    "nat-dst-port": "yes",
    "nat-events": "yes",
}


@dataclass(frozen=True, slots=True)
class TrafficFlowTarget:
    """Where one router exports to, and from which address.

    ``collector_address`` is the hub's tunnel address (``hub_reserved_ip``),
    ``source_address`` the router's own tunnel address (its WireGuard peer)."""

    collector_address: str
    collector_port: int
    source_address: str


#: The target fields that say "this row is ours".
TARGET_IDENTITY_FIELDS: tuple[str, ...] = ("dst-address", "port")


def target_identity(collector_address: str, collector_port: int) -> dict[str, str]:
    """Which ``/ip traffic-flow target`` rows are the platform's: the ones
    exporting to the platform's collector. Any other row is somebody else's
    (a venue's own collector) and is never updated or removed."""
    return {"dst-address": str(collector_address), "port": str(int(collector_port))}


def desired_config(
    target: TrafficFlowTarget, *, nat_events: bool = False
) -> TrafficFlowConfig:
    """Export ON, to ``target``. ``nat_events`` adds IPFIX NAT event export
    (off unless ``traffic_flow_ipfix_nat_events``)."""
    ipfix = dict(_IPFIX)
    if nat_events:
        ipfix.update(_IPFIX_NAT_EVENTS)
    return TrafficFlowConfig(
        settings=dict(_SETTINGS),
        ipfix=ipfix,
        target={
            "dst-address": target.collector_address,
            "port": str(target.collector_port),
            "version": "ipfix",
            "src-address": target.source_address,
        },
        identity=target_identity(target.collector_address, target.collector_port),
    )


def disabled_config(identity: Mapping[str, str] | None = None) -> TrafficFlowConfig:
    """Our target removed, and export OFF unless somebody else's target is
    still there. ``identity`` says which rows are ours; without one nothing
    is removed. IPFIX field toggles are left as they are: they do nothing
    while export is off."""
    return TrafficFlowConfig(
        settings={"enabled": "no"},
        ipfix={},
        target=None,
        identity=dict(identity) if identity else None,
    )


def routeros_major_version(version: str | None) -> int | None:
    if not version:
        return None
    head = version.strip().split(".", 1)[0]
    return int(head) if head.isdigit() else None


def _fields(fields: dict[str, str]) -> str:
    return " ".join(f"{key}={value}" for key, value in fields.items())


def _find(identity: Mapping[str, str]) -> str:
    """``find where`` for our target, e.g. ``dst-address=10.20.0.1 and
    port=2055``. Values are an IP address and a port number built by
    :func:`target_identity`, never free text.

    ASSUMPTION, unmeasured: that RouterOS prints a target's ``dst-address``
    as a bare address, so this comparison matches. If a release prints
    ``10.20.0.1/32`` the find matches nothing and a re-paste would add a
    second target; the device writer does not depend on this (it compares
    with the mask stripped) and its read-back would report the duplicate."""
    return " and ".join(f"{key}={value}" for key, value in identity.items())


#: A stored version that is not 7 skips the section. No stored version at
#: all does NOT: the lines are rendered behind this per-line guard instead,
#: so on a RouterOS 6 device each one does nothing.
_V7_GUARD = ':if ([:pick [/system resource get version] 0 2] = "7.") do={{ {line} }}'


def render_traffic_flow_lines(
    config: TrafficFlowConfig, *, routeros_version: str | None
) -> list[str]:
    """RouterOS script lines for ``config`` (export ON only). Each line is
    one command so ``_idempotent_lines`` can wrap it.

    ``target add`` has no unique key and duplicates on every push -- two
    targets double-count every flow -- so it is guarded by a find on our
    target's own ``dst-address`` + ``port``, followed by a ``set`` that
    converges an existing row and a one-line removal of any extra rows with
    the same identity. The two singleton ``set``s are idempotent by nature.
    The target goes in before export is switched on, the same order the
    device writer uses.

    Three cases by the router's *stored* version:

    * 7.x -- the lines as they are;
    * not recorded -- the same lines, each behind a "RouterOS 7" check the
      device evaluates itself, under a one-line note. A missing database
      value is not a reason to withhold the script;
    * anything else (6.x) -- a comment only. RouterOS 6 spells the target
      differently and lacks ``src-address``."""
    major = routeros_major_version(routeros_version)
    if major is not None and major != 7:
        return [
            TRAFFIC_FLOW_SECTION_HEADER,
            "# traffic-flow skipped: RouterOS 7 required "
            f"(router reports {routeros_version})",
        ]
    if config.target is None or not config.identity:
        raise ValueError("render_traffic_flow_lines renders export ON only")
    find = f"[/ip traffic-flow target find where {_find(config.identity)}]"
    target = _fields(dict(config.target))
    commands = [
        f":if ([:len {find}] = 0) do={{/ip traffic-flow target add {target}}}",
        f"/ip traffic-flow target set {find} {target}",
        f":local wyfyTf {find}; :if ([:len $wyfyTf] > 1) do={{"
        "/ip traffic-flow target remove [:pick $wyfyTf 1 [:len $wyfyTf]]}",
        f"/ip traffic-flow ipfix set {_fields(dict(config.ipfix))}",
        f"/ip traffic-flow set {_fields(dict(config.settings))}",
    ]
    if major == 7:
        return [TRAFFIC_FLOW_SECTION_HEADER, *commands]
    return [
        TRAFFIC_FLOW_SECTION_HEADER,
        "# RouterOS version not recorded for this router: each line below "
        "runs only on RouterOS 7",
        *[_V7_GUARD.format(line=line) for line in commands],
    ]


def render_removal_lines(identity: Mapping[str, str] | None) -> list[str]:
    """RouterOS lines that undo the export, for pasting by hand, in the
    device writer's order: remove OUR target (found by ``dst-address`` +
    ``port``, so a venue's own collector is never touched), then switch
    export off only if no target at all is left. Empty when it is not known
    which target is ours -- there is then nothing safe to remove."""
    if not identity:
        return []
    return [
        f"/ip traffic-flow target remove [find where {_find(identity)}]",
        ":if ([:len [/ip traffic-flow target find]] = 0) do={"
        "/ip traffic-flow set enabled=no}",
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
    export_enabled: bool,
    vendor: str | None,
    routeros_version: str | None,
    peer: _Peer | None,
    server: _Server | None,
    settings: Any,
) -> list[str] | None:
    """What ``render_network_config`` should carry for this router, or
    ``None`` for "no traffic-flow section". The generator-side gate: flag on,
    export switched on for this router (``router_traffic_flow_export``),
    MikroTik, and a tunnel to export over. The device writer applies the
    same gates in ``TrafficFlowDeviceService``."""
    if not settings.traffic_flow_enabled:
        return None
    if not export_enabled:
        return None
    if (vendor or "mikrotik").lower() != "mikrotik":
        return None
    target = traffic_flow_target_for(peer, server, settings)
    if target is None:
        return None
    return render_traffic_flow_lines(
        desired_config(target, nat_events=nat_events_on(settings)),
        routeros_version=routeros_version,
    )


def nat_events_on(settings: Any) -> bool:
    """The one reading of the gate, for the generator and the writer."""
    return bool(getattr(settings, "traffic_flow_ipfix_nat_events", False))

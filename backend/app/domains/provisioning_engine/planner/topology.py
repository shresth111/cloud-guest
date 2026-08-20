"""Network topology analyzer (P8) — pure functions over discovery snapshots.

Detects WAN-inside-bridge conflicts, DHCP clients bound to bridges, and
existing non-WyFy hotspot/DHCP state. Findings are recommendations only —
never auto-applied (spec P8).
"""

from __future__ import annotations

from typing import Any, Protocol

from .constants import CompatibilityCheckStatus, CompatibilityOverall
from .schemas import TopologyFinding, TopologyReport


class TopologySnapshotLike(Protocol):
    interfaces: list[Any] | None
    bridges: list[Any] | None
    dhcp_clients: list[Any] | None
    dhcp_servers: list[Any] | None
    routes: list[Any] | None
    hotspot_state: dict[str, Any] | None


def _row_name(row: Any, *keys: str) -> str | None:
    if isinstance(row, dict):
        for key in keys:
            value = row.get(key)
            if value:
                return str(value)
        return None
    for key in keys:
        value = getattr(row, key, None)
        if value:
            return str(value)
    return None


def _row_bool(row: Any, key: str) -> bool:
    if isinstance(row, dict):
        return bool(row.get(key))
    return bool(getattr(row, key, False))


def _bridge_port_map(bridges: list[Any] | None) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for bridge in bridges or []:
        name = _row_name(bridge, "name")
        if not name:
            continue
        ports = bridge.get("ports", []) if isinstance(bridge, dict) else getattr(
            bridge, "ports", []
        )
        mapping[name] = {str(port) for port in (ports or []) if port}
    return mapping


def _interface_names(interfaces: list[Any] | None) -> set[str]:
    names: set[str] = set()
    for iface in interfaces or []:
        name = _row_name(iface, "name")
        if name:
            names.add(name)
    return names


def _infer_wan_interfaces(snapshot: TopologySnapshotLike) -> set[str]:
    """Best-effort WAN inference when the caller does not pass explicit names."""
    candidates: set[str] = set()
    for client in snapshot.dhcp_clients or []:
        iface = _row_name(client, "interface")
        if iface:
            candidates.add(iface)
    for route in snapshot.routes or []:
        dst = _row_name(route, "dst_address", "dst-address")
        if dst in {"0.0.0.0/0", "::/0"}:
            gateway = _row_name(route, "gateway")
            if gateway and gateway in _interface_names(snapshot.interfaces):
                candidates.add(gateway)
    for iface in snapshot.interfaces or []:
        name = _row_name(iface, "name")
        iface_type = _row_name(iface, "type")
        if name and iface_type in {"pppoe-in", "pppoe-out"}:
            candidates.add(name)
        if name and name.startswith("pppoe-"):
            candidates.add(name)
    return candidates


def _active_default_route_exists(snapshot: TopologySnapshotLike) -> bool:
    for route in snapshot.routes or []:
        dst = _row_name(route, "dst_address", "dst-address")
        if dst not in {"0.0.0.0/0", "::/0"}:
            continue
        active = route.get("active") if isinstance(route, dict) else getattr(
            route, "active", None
        )
        if active is None or bool(active):
            return True
    return False


def _finding(
    *,
    code: str,
    status: CompatibilityCheckStatus,
    summary: str,
    detail: str | None = None,
    resources: list[str] | None = None,
) -> TopologyFinding:
    return TopologyFinding(
        code=code,
        status=status,
        summary=summary,
        detail=detail,
        resources=resources or [],
    )


def analyze_topology(
    snapshot: TopologySnapshotLike,
    *,
    wan_interfaces: set[str] | None = None,
) -> TopologyReport:
    """Analyze bridge/WAN/hotspot/DHCP topology from a discovery snapshot."""
    wan = wan_interfaces if wan_interfaces is not None else _infer_wan_interfaces(snapshot)
    port_map = _bridge_port_map(snapshot.bridges)
    iface_to_bridge: dict[str, str] = {}
    for bridge_name, ports in port_map.items():
        for port in ports:
            iface_to_bridge[port] = bridge_name

    findings: list[TopologyFinding] = []

    for bridge_name, ports in sorted(port_map.items()):
        wan_ports = sorted(port for port in ports if port in wan)
        if wan_ports:
            findings.append(
                _finding(
                    code="wan_in_bridge",
                    status=CompatibilityCheckStatus.WARNING,
                    summary=(
                        f"WAN interface(s) {', '.join(wan_ports)} are bridge ports "
                        f"on {bridge_name}"
                    ),
                    detail=(
                        "WAN interfaces should not remain inside a LAN bridge "
                        "(Rule R1 — plan a bridge-port removal before guest setup)"
                    ),
                    resources=[bridge_name, *wan_ports],
                )
            )

    for client in snapshot.dhcp_clients or []:
        iface = _row_name(client, "interface")
        if not iface:
            continue
        bridge_name = iface_to_bridge.get(iface)
        if bridge_name or iface in port_map:
            bound_bridge = bridge_name or iface
            findings.append(
                _finding(
                    code="dhcp_client_on_bridge",
                    status=CompatibilityCheckStatus.WARNING,
                    summary=f"DHCP client on {iface} (bridge {bound_bridge})",
                    detail=(
                        "DHCP/PPPoE clients should run on the physical WAN "
                        "interface, not a bridge (Rule R2)"
                    ),
                    resources=[iface, bound_bridge],
                )
            )

    for bridge in snapshot.bridges or []:
        name = _row_name(bridge, "name")
        if not name:
            continue
        ports = port_map.get(name, set())
        ether_ports = [
            port
            for port in ports
            if port not in wan and not port.startswith("vlan")
        ]
        if len(ether_ports) > 1:
            findings.append(
                _finding(
                    code="multiple_guest_ports",
                    status=CompatibilityCheckStatus.WARNING,
                    summary=(
                        f"Bridge {name} has multiple LAN ports "
                        f"({', '.join(sorted(ether_ports))})"
                    ),
                    detail=(
                        "Multiple physical ports on one bridge may indicate "
                        "an existing guest/LAN layout to review before provisioning"
                    ),
                    resources=[name, *sorted(ether_ports)],
                )
            )

    hotspot = snapshot.hotspot_state or {}
    server_count = int(hotspot.get("server_count") or 0)
    servers = hotspot.get("servers") or []
    non_managed = [
        str(item.get("name") or item.get("interface") or "hotspot")
        for item in servers
        if isinstance(item, dict) and not item.get("is_wyfy_managed")
    ]
    if server_count > 0 and (non_managed or not servers):
        findings.append(
            _finding(
                code="existing_hotspot",
                status=CompatibilityCheckStatus.WARNING,
                summary="Existing hotspot server(s) detected on the router",
                detail=(
                    "Non-WyFy hotspot configuration requires an explicit "
                    "technician decision (replace / coexist / abort — Rule R7)"
                ),
                resources=non_managed or ["hotspot"],
            )
        )

    non_managed_dhcp = []
    for server in snapshot.dhcp_servers or []:
        if _row_bool(server, "is_wyfy_managed"):
            continue
        label = _row_name(server, "name", "interface") or "dhcp-server"
        non_managed_dhcp.append(label)
    if non_managed_dhcp:
        findings.append(
            _finding(
                code="existing_dhcp_server",
                status=CompatibilityCheckStatus.WARNING,
                summary="Existing non-WyFy DHCP server(s) detected",
                detail="Review DHCP pools before adding guest networks",
                resources=non_managed_dhcp,
            )
        )

    if _active_default_route_exists(snapshot):
        findings.append(
            _finding(
                code="active_default_route",
                status=CompatibilityCheckStatus.PASS,
                summary="An active default route is present in the snapshot",
            )
        )
    else:
        findings.append(
            _finding(
                code="active_default_route",
                status=CompatibilityCheckStatus.WARNING,
                summary="No active default route found in the snapshot",
                detail="Guest provisioning requires WAN connectivity (Rule R9)",
            )
        )

    if port_map:
        findings.append(
            _finding(
                code="bridge_inventory",
                status=CompatibilityCheckStatus.PASS,
                summary=f"Found {len(port_map)} bridge(s) in the snapshot",
                detail=", ".join(sorted(port_map)),
                resources=sorted(port_map),
            )
        )
    else:
        findings.append(
            _finding(
                code="bridge_inventory",
                status=CompatibilityCheckStatus.PASS,
                summary="No bridges reported in the snapshot",
            )
        )

    return TopologyReport(overall=_roll_up(findings), findings=findings)


def _roll_up(findings: list[TopologyFinding]) -> CompatibilityOverall:
    rank = {
        CompatibilityCheckStatus.PASS: 0,
        CompatibilityCheckStatus.WARNING: 1,
        CompatibilityCheckStatus.ERROR: 2,
        CompatibilityCheckStatus.BLOCKED: 3,
    }
    worst = CompatibilityCheckStatus.PASS
    for finding in findings:
        if rank[finding.status] > rank[worst]:
            worst = finding.status
    return CompatibilityOverall(worst.value)


__all__ = [
    "TopologySnapshotLike",
    "analyze_topology",
]

"""Guest network interface availability (P10) — pure functions over snapshots."""

from __future__ import annotations

from typing import Any, Protocol

from .constants import InterfaceAvailabilityStatus
from .schemas import (
    GuestInputRecommendation,
    GuestInterfaceAvailability,
    GuestInterfaceAvailabilityReport,
)
from .topology import TopologySnapshotLike, _bridge_port_map, _infer_wan_interfaces


class GuestInputSnapshotLike(TopologySnapshotLike, Protocol):
    interfaces: list[Any] | None
    vlans: list[Any] | None


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


def _row_bool(row: Any, key: str) -> bool | None:
    value = row.get(key) if isinstance(row, dict) else getattr(row, key, None)
    if value is None:
        return None
    return bool(value)


def _physical_interfaces(snapshot: GuestInputSnapshotLike) -> list[Any]:
    candidates: list[Any] = []
    for iface in snapshot.interfaces or []:
        iface_type = (_row_name(iface, "type") or "").lower()
        name = _row_name(iface, "name")
        if not name:
            continue
        if iface_type in {"", "ether", "ethernet", "sfp", "sfp-sfpplus"}:
            candidates.append(iface)
    return candidates


def _in_use_interfaces(snapshot: GuestInputSnapshotLike) -> set[str]:
    used: set[str] = set()
    for server in snapshot.dhcp_servers or []:
        iface = _row_name(server, "interface")
        if iface:
            used.add(iface)
    hotspot = snapshot.hotspot_state or {}
    for item in hotspot.get("servers") or []:
        if isinstance(item, dict):
            iface = item.get("interface") or item.get("name")
            if iface:
                used.add(str(iface))
    for vlan in snapshot.vlans or []:
        iface = _row_name(vlan, "interface")
        if iface:
            used.add(iface)
    return used


def _guest_bridge_hint(snapshot: GuestInputSnapshotLike) -> str | None:
    for bridge in snapshot.bridges or []:
        name = _row_name(bridge, "name")
        comment = _row_name(bridge, "comment") or ""
        if not name:
            continue
        lowered = name.lower()
        if "guest" in lowered or "guest" in comment.lower():
            return name
        if _row_bool(bridge, "is_wyfy_managed"):
            return name
    return None


def _score_candidate(
    *,
    name: str,
    bridge_name: str | None,
    guest_bridge: str | None,
) -> tuple[int, str]:
    """Lower score is better for recommendation ordering."""
    if guest_bridge and bridge_name == guest_bridge:
        return (0, name)
    if bridge_name is None:
        return (1, name)
    return (2, name)


def evaluate_guest_interface_availability(
    snapshot: GuestInputSnapshotLike,
    *,
    wan_interfaces: set[str] | None = None,
    snapshot_id: str | None = None,
) -> GuestInterfaceAvailabilityReport:
    """Classify each physical port and emit a Wave 1 recommendation."""
    wan = (
        wan_interfaces
        if wan_interfaces is not None
        else _infer_wan_interfaces(snapshot)
    )
    port_map = _bridge_port_map(snapshot.bridges)
    iface_to_bridge: dict[str, str] = {}
    for bridge_name, ports in port_map.items():
        for port in ports:
            iface_to_bridge[port] = bridge_name

    in_use = _in_use_interfaces(snapshot)
    guest_bridge = _guest_bridge_hint(snapshot)
    entries: list[GuestInterfaceAvailability] = []
    pick_candidates: list[tuple[int, str, str]] = []

    for iface in _physical_interfaces(snapshot):
        name = _row_name(iface, "name")
        assert name is not None
        disabled = _row_bool(iface, "disabled")
        if disabled:
            entries.append(
                GuestInterfaceAvailability(
                    name=name,
                    status=InterfaceAvailabilityStatus.DISABLED,
                    detail="Interface is administratively disabled",
                )
            )
            continue

        if name in wan:
            entries.append(
                GuestInterfaceAvailability(
                    name=name,
                    status=InterfaceAvailabilityStatus.WAN,
                    detail="Configured as a WAN uplink",
                )
            )
            continue

        bridge_name = iface_to_bridge.get(name)
        if bridge_name and port_map.get(bridge_name, set()) & wan:
            entries.append(
                GuestInterfaceAvailability(
                    name=name,
                    status=InterfaceAvailabilityStatus.UNAVAILABLE,
                    detail=f"Bridge {bridge_name} carries WAN traffic",
                    bridge=bridge_name,
                )
            )
            continue

        if name in in_use:
            entries.append(
                GuestInterfaceAvailability(
                    name=name,
                    status=InterfaceAvailabilityStatus.IN_USE,
                    detail="DHCP server, hotspot, or VLAN already bound here",
                    bridge=bridge_name,
                )
            )
            continue

        if bridge_name:
            status = InterfaceAvailabilityStatus.BRIDGE_MEMBER
            detail = f"Member of bridge {bridge_name}"
        else:
            status = InterfaceAvailabilityStatus.AVAILABLE
            detail = "Free physical port"

        entries.append(
            GuestInterfaceAvailability(
                name=name,
                status=status,
                detail=detail,
                bridge=bridge_name,
            )
        )
        if status in {
            InterfaceAvailabilityStatus.AVAILABLE,
            InterfaceAvailabilityStatus.BRIDGE_MEMBER,
        }:
            score, sort_name = _score_candidate(
                name=name,
                bridge_name=bridge_name,
                guest_bridge=guest_bridge,
            )
            pick_candidates.append((score, sort_name, name))

    recommended: list[str] = []
    message: str | None = None
    parent_bridge_hint = guest_bridge

    if pick_candidates:
        pick_candidates.sort()
        best_name = pick_candidates[0][2]
        recommended = [best_name]
        message = (
            f"Use {best_name} for guest Wi-Fi"
            if guest_bridge is None
            else f"Use {best_name} on existing guest bridge {guest_bridge}"
        )
        entries = [
            entry.model_copy(
                update={
                    "status": InterfaceAvailabilityStatus.RECOMMENDED,
                }
            )
            if entry.name == best_name
            and entry.status
            in {
                InterfaceAvailabilityStatus.AVAILABLE,
                InterfaceAvailabilityStatus.BRIDGE_MEMBER,
            }
            else entry
            for entry in entries
        ]
    else:
        message = "No suitable guest interface found; review topology findings"

    entries.sort(key=lambda item: item.name)
    return GuestInterfaceAvailabilityReport(
        snapshot_id=snapshot_id,
        interfaces=entries,
        recommendation=GuestInputRecommendation(
            recommended_interfaces=recommended,
            parent_bridge_hint=parent_bridge_hint,
            message=message,
        ),
    )


__all__ = [
    "GuestInputSnapshotLike",
    "evaluate_guest_interface_availability",
]

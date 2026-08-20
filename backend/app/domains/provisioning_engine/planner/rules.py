"""Wave 1 deterministic planner rules (R1–R10)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .constants import (
    DEFAULT_GUEST_BRIDGE_NAME,
    CompatibilityCheckStatus,
    PlanActionType,
    PlanRisk,
    RuleId,
)
from .plan_builder import PlanBuilder
from .schemas import GuestNetworkRequest, PlanConflict, PlanDecision
from .subnet_conflicts import detect_subnet_conflicts
from .topology import TopologySnapshotLike, _bridge_port_map, analyze_topology


class PlanSnapshotLike(TopologySnapshotLike, Protocol):
    interfaces: list[Any] | None
    bridges: list[Any] | None
    routes: list[Any] | None
    ip_addresses: list[Any] | None
    hotspot_state: dict[str, Any] | None
    vlans: list[Any] | None


@dataclass(frozen=True)
class PlanContext:
    snapshot: PlanSnapshotLike
    request: GuestNetworkRequest
    wan_interfaces: set[str]
    wan_gate_passes: bool
    builder: PlanBuilder


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


def _active_default_route_exists(snapshot: PlanSnapshotLike) -> bool:
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


def _bridge_is_wan_tainted(
    bridge_name: str, port_map: dict[str, set[str]], wan: set[str]
) -> bool:
    return bool(port_map.get(bridge_name, set()) & wan)


def _find_suitable_parent_bridge(
    snapshot: PlanSnapshotLike, wan: set[str]
) -> str | None:
    port_map = _bridge_port_map(snapshot.bridges)
    for bridge in snapshot.bridges or []:
        name = _row_name(bridge, "name")
        if not name or _bridge_is_wan_tainted(name, port_map, wan):
            continue
        return name
    return None


def rule_r1_wan_in_bridge(ctx: PlanContext) -> None:
    report = analyze_topology(ctx.snapshot, wan_interfaces=ctx.wan_interfaces)
    for finding in report.findings:
        if finding.code != "wan_in_bridge":
            continue
        resources = finding.resources
        if len(resources) < 2:
            continue
        bridge_name = finding.resources[0]
        wan_ports = finding.resources[1:]
        for port in wan_ports:
            ctx.builder.add_action(
                rule_id=RuleId.R1.value,
                action_type=PlanActionType.REMOVE,
                resource_kind="bridge_port",
                routeros_path="/interface bridge port",
                resource_ref=f"{bridge_name}:{port}",
                summary=f"Remove WAN port {port} from bridge {bridge_name}",
                risk=PlanRisk.LOW,
                details={"bridge": bridge_name, "interface": port},
            )


def rule_r2_dhcp_client_on_bridge(ctx: PlanContext) -> None:
    report = analyze_topology(ctx.snapshot, wan_interfaces=ctx.wan_interfaces)
    for finding in report.findings:
        if finding.code != "dhcp_client_on_bridge":
            continue
        iface = finding.resources[0] if finding.resources else None
        if not iface:
            continue
        ctx.builder.add_action(
            rule_id=RuleId.R2.value,
            action_type=PlanActionType.MODIFY,
            resource_kind="dhcp_client",
            routeros_path="/ip dhcp-client",
            resource_ref=iface,
            summary=f"Move DHCP client from {iface} to physical WAN interface",
            risk=PlanRisk.LOW,
            details={"current_interface": iface},
        )


def rule_r3_pppoe_mapping(ctx: PlanContext) -> None:
    # WAN physical/routing split is enforced on isp_links (Step 4); planner
    # records acknowledgement only when guest work is requested.
    if not ctx.request.guest_interfaces:
        return
    ctx.builder.add_action(
        rule_id=RuleId.R3.value,
        action_type=PlanActionType.NOOP,
        resource_kind="wan_mapping",
        routeros_path="isp_links",
        resource_ref="pppoe-routing",
        summary="PPPoE links use physical/routing interface split from isp_links",
    )


def rule_r4_r5_guest_bridge(ctx: PlanContext) -> None:
    if not ctx.request.guest_interfaces:
        return
    if ctx.builder.blocked:
        return

    parent = ctx.request.parent_bridge
    if parent:
        ctx.builder.add_action(
            rule_id=RuleId.R5.value,
            action_type=PlanActionType.NOOP,
            resource_kind="bridge",
            routeros_path="/interface bridge",
            resource_ref=parent,
            summary=f"Use parent bridge {parent} for guest/VLAN traffic",
        )
        return

    suitable = _find_suitable_parent_bridge(ctx.snapshot, ctx.wan_interfaces)
    if suitable:
        ctx.builder.add_action(
            rule_id=RuleId.R5.value,
            action_type=PlanActionType.NOOP,
            resource_kind="bridge",
            routeros_path="/interface bridge",
            resource_ref=suitable,
            summary=f"Reuse existing bridge {suitable} as guest parent",
        )
        return

    ctx.builder.add_action(
        rule_id=RuleId.R4.value,
        action_type=PlanActionType.CREATE,
        resource_kind="bridge",
        routeros_path="/interface bridge",
        resource_ref=DEFAULT_GUEST_BRIDGE_NAME,
        summary=f"Create managed guest bridge {DEFAULT_GUEST_BRIDGE_NAME}",
        details={"name": DEFAULT_GUEST_BRIDGE_NAME},
    )


def rule_r6_subnet_overlap(ctx: PlanContext) -> None:
    cidrs = [vlan.subnet_cidr for vlan in ctx.request.vlans]
    labels = [vlan.name for vlan in ctx.request.vlans]
    for conflict in detect_subnet_conflicts(
        ctx.snapshot,
        desired_cidrs=cidrs,
        desired_labels=labels or None,
    ):
        ctx.builder.add_conflict(conflict)


def rule_r7_existing_hotspot(ctx: PlanContext) -> None:
    if not ctx.request.guest_interfaces:
        return
    report = analyze_topology(ctx.snapshot, wan_interfaces=ctx.wan_interfaces)
    for finding in report.findings:
        if finding.code != "existing_hotspot":
            continue
        ctx.builder.add_decision(
            PlanDecision(
                code="existing_hotspot",
                summary=finding.summary,
                detail=finding.detail,
                options=["replace", "coexist", "abort"],
            )
        )


def rule_r8_wan_verification_gate(ctx: PlanContext) -> None:
    if not ctx.request.guest_interfaces:
        return
    if ctx.wan_gate_passes:
        return
    ctx.builder.add_conflict(
        PlanConflict(
            code="wan_verification_gate",
            status=CompatibilityCheckStatus.BLOCKED,
            summary="WAN verification gate did not pass (R8)",
            detail="Run WAN verification and ensure all enabled links are ONLINE",
        )
    )


def rule_r9_default_route_gate(ctx: PlanContext) -> None:
    if not ctx.request.guest_interfaces:
        return
    if _active_default_route_exists(ctx.snapshot):
        return
    ctx.builder.add_conflict(
        PlanConflict(
            code="no_default_route",
            status=CompatibilityCheckStatus.BLOCKED,
            summary="No active default route in discovery snapshot (R9)",
            detail="Guest provisioning requires WAN connectivity",
        )
    )


def rule_r10_management_safety(ctx: PlanContext) -> None:
    # Wave 1: flag guest actions touching management paths for later safety net.
    if not ctx.request.guest_interfaces:
        return
    for action in list(ctx.builder.actions):
        if action.resource_kind in {"bridge_port", "dhcp_client"}:
            ctx.builder.add_action(
                rule_id=RuleId.R10.value,
                action_type=PlanActionType.NOOP,
                resource_kind="safety_review",
                routeros_path="management",
                resource_ref=action.resource_ref,
                summary=(
                    f"Review management connectivity risk for {action.resource_ref}"
                ),
                risk=PlanRisk.MANAGEMENT_CONNECTIVITY,
                details={"related_action_seq": action.seq},
            )


RULE_REGISTRY: tuple[Callable[[PlanContext], None], ...] = (
    rule_r8_wan_verification_gate,
    rule_r9_default_route_gate,
    rule_r6_subnet_overlap,
    rule_r1_wan_in_bridge,
    rule_r2_dhcp_client_on_bridge,
    rule_r3_pppoe_mapping,
    rule_r4_r5_guest_bridge,
    rule_r7_existing_hotspot,
    rule_r10_management_safety,
)


__all__ = [
    "PlanSnapshotLike",
    "PlanContext",
    "RULE_REGISTRY",
]

"""Management-connectivity risk detection (R10)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .constants import PlanActionType
from .schemas import PlanAction


class ManagementSnapshotLike(Protocol):
    routes: list[Any] | None
    ip_addresses: list[Any] | None


@dataclass(frozen=True)
class ManagementRiskAssessment:
    risky: bool
    reason: str | None = None


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


def active_default_route_gateway(snapshot: ManagementSnapshotLike) -> str | None:
    for route in snapshot.routes or []:
        dst = _row_name(route, "dst_address", "dst-address")
        if dst not in {"0.0.0.0/0", "::/0"}:
            continue
        active = route.get("active") if isinstance(route, dict) else getattr(
            route, "active", None
        )
        if active is None or bool(active):
            return _row_name(route, "gateway")
    return None


def _management_sensitive_interfaces(
    snapshot: ManagementSnapshotLike, wan_interfaces: set[str]
) -> set[str]:
    sensitive = set(wan_interfaces)
    gateway = active_default_route_gateway(snapshot)
    if gateway:
        sensitive.add(gateway)
    for address in snapshot.ip_addresses or []:
        iface = _row_name(address, "interface")
        if iface:
            sensitive.add(iface)
    return sensitive


def _action_touches_interface(action: PlanAction, interface: str) -> bool:
    if interface in action.resource_ref:
        return True
    details = action.details
    for key in ("interface", "current_interface", "bridge"):
        value = details.get(key)
        if value and str(value) == interface:
            return True
    if action.resource_kind == "bridge_port" and ":" in action.resource_ref:
        _, port = action.resource_ref.split(":", 1)
        return port == interface
    return False


def assess_management_risk(
    action: PlanAction,
    *,
    snapshot: ManagementSnapshotLike,
    wan_interfaces: set[str],
) -> ManagementRiskAssessment:
    if action.action_type is PlanActionType.NOOP:
        return ManagementRiskAssessment(risky=False)

    sensitive = _management_sensitive_interfaces(snapshot, wan_interfaces)
    for iface in sensitive:
        if _action_touches_interface(action, iface):
            return ManagementRiskAssessment(
                risky=True,
                reason=f"Touches management-sensitive interface {iface}",
            )

    if (
        action.resource_kind == "dhcp_client"
        and action.action_type is PlanActionType.MODIFY
    ):
        iface = str(action.details.get("current_interface") or action.resource_ref)
        if iface in {"bridgeLocal", "bridge"} or iface.startswith("bridge"):
            return ManagementRiskAssessment(
                risky=True,
                reason=f"Moves DHCP client off shared bridge interface {iface}",
            )

    return ManagementRiskAssessment(risky=False)


def plan_requires_safety_net(actions: list[PlanAction]) -> bool:
    from .constants import PlanRisk

    return any(action.risk is PlanRisk.MANAGEMENT_CONNECTIVITY for action in actions)


__all__ = [
    "ManagementRiskAssessment",
    "active_default_route_gateway",
    "assess_management_risk",
    "plan_requires_safety_net",
]

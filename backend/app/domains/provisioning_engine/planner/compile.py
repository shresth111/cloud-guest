"""Plan-to-RouterOS script compiler (Wave 1 Step 10)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.domains.network_config.profiles.constants import SECRET_PLACEHOLDER_PREFIX
from app.domains.network_config.profiles.guest import (
    render_add_bridge_ports,
    render_create_bridge,
    render_dhcp_client_cleanup,
    render_remove_bridge_port,
)
from app.domains.network_config.profiles.registry import ProfileId, profile_for_action

from .constants import PlanActionType, PlanStatus
from .schemas import ConfigurationPlanResponse, PlanAction

_SECRET_REF_PATTERN = re.compile(
    re.escape(SECRET_PLACEHOLDER_PREFIX) + r"([^}]+)\}\}"
)


@dataclass(frozen=True)
class CompileResult:
    script: str
    profiles_used: list[str] = field(default_factory=list)
    secret_refs: list[str] = field(default_factory=list)
    line_count: int = 0


def resolve_parent_bridge(plan: ConfigurationPlanResponse) -> str | None:
    if plan.requested_config.parent_bridge:
        return plan.requested_config.parent_bridge
    for action in plan.actions:
        if action.resource_kind != "bridge":
            continue
        if action.action_type is PlanActionType.CREATE:
            return str(action.details.get("name") or action.resource_ref)
        if action.action_type is PlanActionType.NOOP:
            return action.resource_ref
    return None


def _extract_secret_refs(script: str) -> list[str]:
    return sorted(set(_SECRET_REF_PATTERN.findall(script)))


def compile_configuration_plan(plan: ConfigurationPlanResponse) -> CompileResult:
    """Map approved plan actions to profile renderers and assemble script text."""
    lines: list[str] = ["# --- WyFyGuest configuration plan (managed) ---"]
    profiles_used: list[str] = []

    for action in sorted(plan.actions, key=lambda item: item.seq):
        profile_id = profile_for_action(action)
        if profile_id is None:
            continue
        lines.extend(_render_action(action, profile_id))
        profiles_used.append(profile_id.value)

    parent_bridge = resolve_parent_bridge(plan)
    guest_ports = plan.requested_config.guest_interfaces
    if parent_bridge and guest_ports:
        lines.extend(
            render_add_bridge_ports(bridge=parent_bridge, interfaces=guest_ports)
        )
        profiles_used.append(ProfileId.GUEST_BRIDGE_PORTS.value)

    script = "\n".join(lines)
    secret_refs = _extract_secret_refs(script)
    return CompileResult(
        script=script,
        profiles_used=profiles_used,
        secret_refs=secret_refs,
        line_count=len(lines),
    )


def _render_action(action: PlanAction, profile_id: ProfileId) -> list[str]:
    if profile_id is ProfileId.GUEST_BRIDGE_CREATE:
        name = str(action.details.get("name") or action.resource_ref)
        return render_create_bridge(name)
    if profile_id is ProfileId.GUEST_BRIDGE_PORT_REMOVE:
        bridge = str(action.details.get("bridge", ""))
        interface = str(action.details.get("interface", ""))
        if not bridge or not interface:
            return []
        return render_remove_bridge_port(bridge=bridge, interface=interface)
    if profile_id is ProfileId.GUEST_DHCP_CLIENT_CLEANUP:
        iface = str(action.details.get("current_interface") or action.resource_ref)
        return render_dhcp_client_cleanup(iface)
    return []


def plan_is_compilable(plan: ConfigurationPlanResponse) -> bool:
    if plan.status not in {PlanStatus.APPROVED, PlanStatus.RENDERING}:
        return False
    if plan.conflicts:
        return False
    result = compile_configuration_plan(plan)
    return result.line_count > 1


__all__ = [
    "CompileResult",
    "compile_configuration_plan",
    "plan_is_compilable",
    "resolve_parent_bridge",
]

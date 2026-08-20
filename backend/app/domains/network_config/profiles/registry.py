"""Profile registry mapping plan actions to renderer profiles."""

from __future__ import annotations

from enum import StrEnum

from app.domains.provisioning_engine.planner.constants import PlanActionType
from app.domains.provisioning_engine.planner.schemas import PlanAction


class ProfileId(StrEnum):
    GUEST_BRIDGE_CREATE = "guest_bridge_create"
    GUEST_BRIDGE_PORT_REMOVE = "guest_bridge_port_remove"
    GUEST_DHCP_CLIENT_CLEANUP = "guest_dhcp_client_cleanup"
    GUEST_BRIDGE_PORTS = "guest_bridge_ports"


_ACTION_PROFILES: dict[tuple[str, PlanActionType], ProfileId] = {
    ("bridge", PlanActionType.CREATE): ProfileId.GUEST_BRIDGE_CREATE,
    ("bridge_port", PlanActionType.REMOVE): ProfileId.GUEST_BRIDGE_PORT_REMOVE,
    ("dhcp_client", PlanActionType.MODIFY): ProfileId.GUEST_DHCP_CLIENT_CLEANUP,
}


def profile_for_action(action: PlanAction) -> ProfileId | None:
    """Return the profile id for a renderable plan action, if any."""
    return _ACTION_PROFILES.get((action.resource_kind, action.action_type))


__all__ = ["ProfileId", "profile_for_action"]

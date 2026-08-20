"""Configuration plan builder orchestrator."""

from __future__ import annotations

from .constants import PLAN_ENGINE_VERSION, PlanStatus
from .plan_builder import PlanBuilder
from .rules import RULE_REGISTRY, PlanContext, PlanSnapshotLike
from .schemas import ConfigurationPlanResponse, GuestNetworkRequest


def build_configuration_plan(
    *,
    snapshot: PlanSnapshotLike,
    snapshot_id: str,
    router_id: str,
    request: GuestNetworkRequest,
    wan_interfaces: set[str],
    wan_gate_passes: bool,
) -> ConfigurationPlanResponse:
    """Run the ordered rule registry and return an in-memory plan preview."""
    builder = PlanBuilder()
    context = PlanContext(
        snapshot=snapshot,
        request=request,
        wan_interfaces=wan_interfaces,
        wan_gate_passes=wan_gate_passes,
        builder=builder,
    )
    for rule in RULE_REGISTRY:
        rule(context)
        if builder.blocked:
            break

    status = builder.resolve_status()
    if status is PlanStatus.DRAFT and builder.actions and not builder.decisions:
        status = PlanStatus.AWAITING_APPROVAL

    return ConfigurationPlanResponse(
        id="",
        router_id=router_id,
        snapshot_id=snapshot_id,
        status=status,
        engine_version=PLAN_ENGINE_VERSION,
        requested_config=request,
        actions=builder.actions,
        conflicts=builder.conflicts,
        decisions=builder.decisions,
        summary=builder.summary(),
    )


def plan_to_persist_dict(
    plan: ConfigurationPlanResponse,
    *,
    router_id: object,
    organization_id: object,
    location_id: object,
    snapshot_id: object,
    actor_user_id: object | None,
) -> dict[str, object]:
    return {
        "router_id": router_id,
        "organization_id": organization_id,
        "location_id": location_id,
        "snapshot_id": snapshot_id,
        "status": plan.status.value,
        "engine_version": plan.engine_version,
        "actions": [action.model_dump(mode="json") for action in plan.actions],
        "conflicts": [conflict.model_dump(mode="json") for conflict in plan.conflicts],
        "created_by": actor_user_id,
    }


__all__ = ["build_configuration_plan", "plan_to_persist_dict"]

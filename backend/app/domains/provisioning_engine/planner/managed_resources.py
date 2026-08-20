"""Derive ``managed_router_resources`` rows from a rendered plan."""

from __future__ import annotations

import hashlib
import uuid

from app.domains.network_config.profiles.constants import wyfy_comment

from .constants import ManagedResourceOp, ManagedResourceStatus, PlanActionType
from .schemas import ConfigurationPlanResponse, PlanAction


def _comment_tag_for_action(action: PlanAction) -> str | None:
    if action.action_type is PlanActionType.CREATE and action.resource_kind == "bridge":
        name = str(action.details.get("name") or action.resource_ref)
        return wyfy_comment("bridge", "guest") if "WYFYGUEST" in name else None
    if (
        action.action_type is PlanActionType.REMOVE
        and action.resource_kind == "bridge_port"
    ):
        bridge = str(action.details.get("bridge", ""))
        interface = str(action.details.get("interface", ""))
        if bridge and interface:
            return f"{bridge}:{interface}"
    return action.resource_ref or None


def _op_for_action(action: PlanAction) -> ManagedResourceOp | None:
    if action.action_type is PlanActionType.CREATE:
        return ManagedResourceOp.CREATED
    if action.action_type is PlanActionType.MODIFY:
        return ManagedResourceOp.MODIFIED
    if action.action_type is PlanActionType.REMOVE:
        return ManagedResourceOp.REMOVED
    return None


def build_managed_resource_rows(
    plan: ConfigurationPlanResponse,
    *,
    plan_id: uuid.UUID,
    router_id: uuid.UUID,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for action in plan.actions:
        op = _op_for_action(action)
        comment_tag = _comment_tag_for_action(action)
        if op is None or not comment_tag:
            continue
        payload = f"{action.resource_kind}:{action.resource_ref}:{action.summary}"
        rows.append(
            {
                "router_id": router_id,
                "organization_id": organization_id,
                "location_id": location_id,
                "plan_id": plan_id,
                "resource_kind": action.resource_kind,
                "routeros_path": action.routeros_path,
                "comment_tag": comment_tag,
                "desired_state_hash": hashlib.sha256(
                    payload.encode("utf-8")
                ).hexdigest(),
                "op": op.value,
                "status": ManagedResourceStatus.PENDING.value,
            }
        )
    return rows


__all__ = ["build_managed_resource_rows"]

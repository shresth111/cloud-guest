"""Mutable plan accumulator for the Wave 1 rule engine."""

from __future__ import annotations

from .constants import CompatibilityCheckStatus, PlanActionType, PlanRisk, PlanStatus
from .schemas import PlanAction, PlanConflict, PlanDecision, PlanSummary


class PlanBuilder:
    def __init__(self) -> None:
        self.actions: list[PlanAction] = []
        self.conflicts: list[PlanConflict] = []
        self.decisions: list[PlanDecision] = []
        self._seq = 0

    @property
    def blocked(self) -> bool:
        return any(
            conflict.status is CompatibilityCheckStatus.BLOCKED
            for conflict in self.conflicts
        )

    def add_action(
        self,
        *,
        rule_id: str,
        action_type: PlanActionType,
        resource_kind: str,
        routeros_path: str,
        resource_ref: str,
        summary: str,
        risk: PlanRisk = PlanRisk.NONE,
        details: dict | None = None,
    ) -> None:
        self._seq += 1
        self.actions.append(
            PlanAction(
                seq=self._seq,
                rule_id=rule_id,
                action_type=action_type,
                resource_kind=resource_kind,
                routeros_path=routeros_path,
                resource_ref=resource_ref,
                summary=summary,
                risk=risk,
                details=details or {},
            )
        )

    def add_conflict(self, conflict: PlanConflict) -> None:
        self.conflicts.append(conflict)

    def add_decision(self, decision: PlanDecision) -> None:
        self.decisions.append(decision)

    def upgrade_action_risk(
        self,
        seq: int,
        risk: PlanRisk,
        *,
        reason: str,
    ) -> None:
        for index, action in enumerate(self.actions):
            if action.seq != seq:
                continue
            details = dict(action.details)
            details["management_risk_reason"] = reason
            self.actions[index] = action.model_copy(
                update={"risk": risk, "details": details}
            )
            return

    def resolve_status(self) -> PlanStatus:
        if self.blocked:
            return PlanStatus.BLOCKED
        if self.decisions:
            return PlanStatus.AWAITING_APPROVAL
        return PlanStatus.DRAFT

    def summary(self) -> PlanSummary:
        highest = PlanRisk.NONE
        rank = {
            PlanRisk.NONE: 0,
            PlanRisk.LOW: 1,
            PlanRisk.MANAGEMENT_CONNECTIVITY: 2,
        }
        for action in self.actions:
            if rank[action.risk] > rank[highest]:
                highest = action.risk
        return PlanSummary(
            action_count=len(self.actions),
            conflict_count=len(self.conflicts),
            decision_count=len(self.decisions),
            highest_risk=highest,
        )


__all__ = ["PlanBuilder"]

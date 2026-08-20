"""Unit tests for R10 management safety detection."""

from __future__ import annotations

from app.domains.provisioning_engine.planner.constants import (
    PlanActionType,
    PlanRisk,
    RuleId,
)
from app.domains.provisioning_engine.planner.management_safety import (
    assess_management_risk,
)
from app.domains.provisioning_engine.planner.schemas import PlanAction


def test_assess_flags_wan_bridge_port_removal() -> None:
    action = PlanAction(
        seq=1,
        rule_id=RuleId.R1.value,
        action_type=PlanActionType.REMOVE,
        resource_kind="bridge_port",
        routeros_path="/interface bridge port",
        resource_ref="bridgeLocal:ether1",
        summary="Remove WAN port",
        details={"bridge": "bridgeLocal", "interface": "ether1"},
    )
    assessment = assess_management_risk(
        action,
        snapshot=type("Snap", (), {"routes": [], "ip_addresses": []})(),
        wan_interfaces={"ether1"},
    )
    assert assessment.risky is True


def test_assess_flags_dhcp_on_bridge_local() -> None:
    action = PlanAction(
        seq=1,
        rule_id=RuleId.R2.value,
        action_type=PlanActionType.MODIFY,
        resource_kind="dhcp_client",
        routeros_path="/ip dhcp-client",
        resource_ref="bridgeLocal",
        summary="Move DHCP client",
        details={"current_interface": "bridgeLocal"},
    )
    assessment = assess_management_risk(
        action,
        snapshot=type("Snap", (), {"routes": [], "ip_addresses": []})(),
        wan_interfaces=set(),
    )
    assert assessment.risky is True


def test_assess_ignores_guest_bridge_create() -> None:
    action = PlanAction(
        seq=1,
        rule_id=RuleId.R4.value,
        action_type=PlanActionType.CREATE,
        resource_kind="bridge",
        routeros_path="/interface bridge",
        resource_ref="WYFYGUEST-bridge-guest",
        summary="Create guest bridge",
        details={"name": "WYFYGUEST-bridge-guest"},
        risk=PlanRisk.NONE,
    )
    assessment = assess_management_risk(
        action,
        snapshot=type("Snap", (), {"routes": [], "ip_addresses": []})(),
        wan_interfaces={"ether1"},
    )
    assert assessment.risky is False

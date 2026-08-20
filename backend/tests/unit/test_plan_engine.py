"""Unit tests for Wave 1 Step 9 configuration plan rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.domains.provisioning_engine.planner.constants import (
    PlanActionType,
    PlanRisk,
    PlanStatus,
    RuleId,
)
from app.domains.provisioning_engine.planner.plan_engine import build_configuration_plan
from app.domains.provisioning_engine.planner.schemas import (
    BridgeSnapshot,
    GuestNetworkRequest,
    GuestVlanRequest,
    InterfaceSnapshot,
    IpAddressSnapshot,
    RouteSnapshot,
)


@dataclass
class FakeSnapshot:
    interfaces: list[Any] = field(default_factory=list)
    bridges: list[Any] = field(default_factory=list)
    dhcp_clients: list[Any] = field(default_factory=list)
    dhcp_servers: list[Any] = field(default_factory=list)
    routes: list[Any] = field(default_factory=list)
    ip_addresses: list[Any] = field(default_factory=list)
    hotspot_state: dict[str, Any] = field(default_factory=dict)
    vlans: list[Any] = field(default_factory=list)


def test_r8_blocks_guest_plan_when_wan_gate_fails() -> None:
    snapshot = FakeSnapshot(
        interfaces=[InterfaceSnapshot(name="ether2", type="ether")],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    plan = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=False,
    )
    assert plan.status is PlanStatus.BLOCKED
    assert any(c.code == "wan_verification_gate" for c in plan.conflicts)


def test_r6_blocks_on_subnet_overlap() -> None:
    snapshot = FakeSnapshot(
        ip_addresses=[
            IpAddressSnapshot(address="192.168.88.1/24", interface="bridge1")
        ],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    plan = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(
            guest_interfaces=["ether2"],
            vlan_mode=True,
            vlans=[
                GuestVlanRequest(
                    vlan_id=10,
                    name="guest",
                    subnet_cidr="192.168.88.0/24",
                )
            ],
        ),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    assert plan.status is PlanStatus.BLOCKED
    assert any(c.code == "subnet_overlap" for c in plan.conflicts)


def test_r1_emits_bridge_port_removal() -> None:
    snapshot = FakeSnapshot(
        interfaces=[
            InterfaceSnapshot(name="ether1", type="ether"),
            InterfaceSnapshot(name="ether2", type="ether"),
        ],
        bridges=[BridgeSnapshot(name="bridgeLocal", ports=["ether1", "ether2"])],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    plan = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    removals = [
        action
        for action in plan.actions
        if action.rule_id == RuleId.R1.value
        and action.action_type is PlanActionType.REMOVE
    ]
    assert removals
    assert removals[0].resource_ref == "bridgeLocal:ether1"


def test_r4_creates_guest_bridge_when_none_exists() -> None:
    snapshot = FakeSnapshot(
        interfaces=[InterfaceSnapshot(name="ether2", type="ether")],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    plan = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    creates = [a for a in plan.actions if a.action_type is PlanActionType.CREATE]
    assert any("WYFYGUEST-bridge-guest" in a.summary for a in creates)


def test_r7_adds_hotspot_decision() -> None:
    snapshot = FakeSnapshot(
        interfaces=[InterfaceSnapshot(name="ether2", type="ether")],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
        hotspot_state={
            "server_count": 1,
            "servers": [{"name": "hotspot1", "is_wyfy_managed": False}],
        },
    )
    plan = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    assert plan.decisions
    assert plan.decisions[0].code == "existing_hotspot"
    assert "replace" in plan.decisions[0].options


def test_r10_flags_management_risk_for_r1_actions() -> None:
    snapshot = FakeSnapshot(
        interfaces=[
            InterfaceSnapshot(name="ether1", type="ether"),
            InterfaceSnapshot(name="ether2", type="ether"),
        ],
        bridges=[BridgeSnapshot(name="bridgeLocal", ports=["ether1"])],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    plan = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    r1 = [a for a in plan.actions if a.rule_id == RuleId.R1.value]
    assert r1
    assert r1[0].risk is PlanRisk.MANAGEMENT_CONNECTIVITY
    assert r1[0].details.get("management_risk_reason")

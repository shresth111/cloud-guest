"""Unit tests for Wave 1 Step 10 plan-to-script compiler."""

from __future__ import annotations

from app.domains.network_config.profiles.constants import (
    EMIT_COMMENT_PREFIX,
    is_managed_comment,
    secret_placeholder,
    wyfy_comment,
)
from app.domains.provisioning_engine.planner.compile import (
    compile_configuration_plan,
    resolve_parent_bridge,
)
from app.domains.provisioning_engine.planner.constants import (
    PlanActionType,
    PlanStatus,
    RuleId,
)
from app.domains.provisioning_engine.planner.plan_engine import build_configuration_plan
from app.domains.provisioning_engine.planner.schemas import (
    BridgeSnapshot,
    ConfigurationPlanResponse,
    GuestNetworkRequest,
    GuestVlanRequest,
    InterfaceSnapshot,
    IpAddressSnapshot,
    PlanAction,
    PlanSummary,
    RouteSnapshot,
)
from tests.unit.test_plan_engine import FakeSnapshot


def test_wyfy_comment_and_dual_recognition() -> None:
    assert wyfy_comment("bridge", "guest") == "WYFYGUEST-bridge-guest"
    assert is_managed_comment("WYFYGUEST-bridge-guest") is True
    assert is_managed_comment("cloudguest-nat-wan1") is True
    assert is_managed_comment("local-bridge") is False
    assert EMIT_COMMENT_PREFIX == "WYFYGUEST-"


def test_secret_placeholder_format() -> None:
    assert secret_placeholder("pppoe-wan1") == "{{WYFYGUEST_SECRET:pppoe-wan1}}"


def test_compile_r1_bridge_port_removal() -> None:
    snapshot = FakeSnapshot(
        interfaces=[
            InterfaceSnapshot(name="ether1", type="ether"),
            InterfaceSnapshot(name="ether2", type="ether"),
        ],
        bridges=[BridgeSnapshot(name="bridgeLocal", ports=["ether1"])],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    preview = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    preview.status = PlanStatus.APPROVED
    result = compile_configuration_plan(preview)
    assert "guest_bridge_port_remove" in result.profiles_used
    assert "bridgeLocal" in result.script
    assert "ether1" in result.script
    assert "WYFYGUEST-bridge-port-guest-1" in result.script


def test_compile_creates_guest_bridge_and_ports() -> None:
    snapshot = FakeSnapshot(
        interfaces=[InterfaceSnapshot(name="ether2", type="ether")],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    preview = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    preview.status = PlanStatus.APPROVED
    result = compile_configuration_plan(preview)
    assert "guest_bridge_create" in result.profiles_used
    assert "guest_bridge_ports" in result.profiles_used
    assert "WYFYGUEST-bridge-guest" in result.script
    assert resolve_parent_bridge(preview) == "WYFYGUEST-bridge-guest"


def test_compile_r2_dhcp_cleanup() -> None:
    plan = ConfigurationPlanResponse(
        id="plan-1",
        router_id="router-1",
        snapshot_id="snap-1",
        status=PlanStatus.APPROVED,
        engine_version="wave1-1",
        requested_config=GuestNetworkRequest(guest_interfaces=[]),
        actions=[
            PlanAction(
                seq=1,
                rule_id=RuleId.R2.value,
                action_type=PlanActionType.MODIFY,
                resource_kind="dhcp_client",
                routeros_path="/ip dhcp-client",
                resource_ref="bridgeLocal",
                summary="Move DHCP client",
                details={"current_interface": "bridgeLocal"},
            )
        ],
        conflicts=[],
        decisions=[],
        summary=PlanSummary(),
    )
    result = compile_configuration_plan(plan)
    assert "guest_dhcp_client_cleanup" in result.profiles_used
    assert "bridgeLocal" in result.script


def test_compile_includes_safety_net_for_management_risk() -> None:
    snapshot = FakeSnapshot(
        interfaces=[
            InterfaceSnapshot(name="ether1", type="ether"),
            InterfaceSnapshot(name="ether2", type="ether"),
        ],
        bridges=[BridgeSnapshot(name="bridgeLocal", ports=["ether1"])],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    preview = build_configuration_plan(
        snapshot=snapshot,
        snapshot_id="snap-1",
        router_id="router-1",
        request=GuestNetworkRequest(guest_interfaces=["ether2"]),
        wan_interfaces={"ether1"},
        wan_gate_passes=True,
    )
    preview.status = PlanStatus.APPROVED
    result = compile_configuration_plan(preview)
    assert "safety_revert_scheduler" in result.profiles_used
    assert "WYFYGUEST-safety-revert" in result.script


def test_compile_skips_blocked_conflicts_in_preview() -> None:
    snapshot = FakeSnapshot(
        ip_addresses=[
            IpAddressSnapshot(address="192.168.88.1/24", interface="bridge1")
        ],
        routes=[RouteSnapshot(dst_address="0.0.0.0/0", gateway="ether1", active=True)],
    )
    preview = build_configuration_plan(
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
    assert preview.status is PlanStatus.BLOCKED
    result = compile_configuration_plan(preview)
    assert result.profiles_used == []

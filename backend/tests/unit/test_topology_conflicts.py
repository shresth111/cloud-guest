"""Unit tests for Wave 1 Step 7 topology analyzer (P8) and subnet conflicts (P9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from app.domains.provisioning_engine.planner.constants import (
    CompatibilityCheckStatus,
    CompatibilityOverall,
)
from app.domains.provisioning_engine.planner.schemas import (
    BridgeSnapshot,
    DhcpClientSnapshot,
    DhcpServerSnapshot,
    IpAddressSnapshot,
    RouteSnapshot,
)
from app.domains.provisioning_engine.planner.subnet_conflicts import (
    collect_snapshot_networks,
    detect_subnet_conflicts,
    networks_overlap,
    parse_network,
)
from app.domains.provisioning_engine.planner.topology import analyze_topology


@dataclass
class FakeSnapshot:
    interfaces: list[Any] = field(default_factory=list)
    bridges: list[Any] = field(default_factory=list)
    ip_addresses: list[Any] = field(default_factory=list)
    dhcp_clients: list[Any] = field(default_factory=list)
    dhcp_servers: list[Any] = field(default_factory=list)
    routes: list[Any] = field(default_factory=list)
    hotspot_state: dict[str, Any] = field(default_factory=dict)


class TestParseNetwork:
    def test_parses_host_bits_in_cidr(self) -> None:
        net = parse_network("192.168.10.5/24")
        assert str(net) == "192.168.10.0/24"

    def test_parses_bare_ip_as_host_route(self) -> None:
        net = parse_network("10.0.0.1")
        assert str(net) == "10.0.0.1/32"


class TestNetworksOverlap:
    def test_overlapping_subnets(self) -> None:
        assert networks_overlap("192.168.1.0/24", "192.168.1.128/25")

    def test_disjoint_subnets(self) -> None:
        assert not networks_overlap("192.168.1.0/24", "192.168.2.0/24")


class TestDetectSubnetConflicts:
    def test_detects_desired_vs_snapshot_overlap(self) -> None:
        snapshot = FakeSnapshot(
            ip_addresses=[
                IpAddressSnapshot(address="192.168.50.1/24", interface="bridge1")
            ]
        )
        conflicts = detect_subnet_conflicts(
            snapshot, desired_cidrs=["192.168.50.0/24"]
        )
        assert len(conflicts) == 1
        assert conflicts[0].code == "subnet_overlap"
        assert conflicts[0].status is CompatibilityCheckStatus.BLOCKED

    def test_detects_desired_vs_desired_overlap(self) -> None:
        snapshot = FakeSnapshot()
        conflicts = detect_subnet_conflicts(
            snapshot,
            desired_cidrs=["10.10.0.0/16", "10.10.5.0/24"],
            desired_labels=["vlan-a", "vlan-b"],
        )
        assert len(conflicts) == 1
        assert "vlan-a" in conflicts[0].detail
        assert "vlan-b" in conflicts[0].detail

    def test_no_conflict_for_disjoint_networks(self) -> None:
        snapshot = FakeSnapshot(
            ip_addresses=[IpAddressSnapshot(address="172.16.0.1/24", interface="lan")]
        )
        conflicts = detect_subnet_conflicts(
            snapshot, desired_cidrs=["192.168.88.0/24"]
        )
        assert conflicts == []

    def test_collect_snapshot_networks_includes_routes(self) -> None:
        snapshot = FakeSnapshot(
            ip_addresses=[IpAddressSnapshot(address="10.1.0.1/24", interface="lan")],
            routes=[RouteSnapshot(dst_address="10.2.0.0/24", gateway="10.1.0.1")],
        )
        networks = collect_snapshot_networks(snapshot)
        labels = {label for label, _cidr in networks}
        assert any(label.startswith("snapshot.ip_addresses") for label in labels)
        assert any(label.startswith("snapshot.routes") for label in labels)

    def test_mismatched_desired_labels_raises(self) -> None:
        snapshot = FakeSnapshot()
        with pytest.raises(ValueError, match="desired_labels"):
            detect_subnet_conflicts(
                snapshot,
                desired_cidrs=["10.0.0.0/24", "10.1.0.0/24"],
                desired_labels=["only-one"],
            )


class TestAnalyzeTopology:
    def test_wan_in_bridge_is_warning(self) -> None:
        snapshot = FakeSnapshot(
            bridges=[
                BridgeSnapshot(
                    name="bridgeLocal",
                    ports=["ether1", "ether2"],
                )
            ],
            dhcp_clients=[DhcpClientSnapshot(interface="ether1", status="bound")],
        )
        report = analyze_topology(snapshot, wan_interfaces={"ether1"})
        codes = [finding.code for finding in report.findings]
        assert "wan_in_bridge" in codes
        wan_finding = next(f for f in report.findings if f.code == "wan_in_bridge")
        assert wan_finding.status is CompatibilityCheckStatus.WARNING
        assert report.overall is CompatibilityOverall.WARNING

    def test_dhcp_client_on_bridge_is_warning(self) -> None:
        snapshot = FakeSnapshot(
            bridges=[BridgeSnapshot(name="bridgeLocal", ports=["ether1"])],
            dhcp_clients=[DhcpClientSnapshot(interface="bridgeLocal", status="bound")],
        )
        report = analyze_topology(snapshot)
        assert any(f.code == "dhcp_client_on_bridge" for f in report.findings)

    def test_existing_hotspot_is_warning(self) -> None:
        snapshot = FakeSnapshot(
            hotspot_state={
                "server_count": 1,
                "servers": [{"name": "hotspot1", "is_wyfy_managed": False}],
            }
        )
        report = analyze_topology(snapshot)
        hotspot = next(f for f in report.findings if f.code == "existing_hotspot")
        assert hotspot.status is CompatibilityCheckStatus.WARNING

    def test_existing_dhcp_server_is_warning(self) -> None:
        snapshot = FakeSnapshot(
            dhcp_servers=[
                DhcpServerSnapshot(
                    name="dhcp1",
                    interface="bridgeLocal",
                    is_wyfy_managed=False,
                )
            ]
        )
        report = analyze_topology(snapshot)
        assert any(f.code == "existing_dhcp_server" for f in report.findings)

    def test_active_default_route_passes(self) -> None:
        snapshot = FakeSnapshot(
            routes=[
                RouteSnapshot(
                    dst_address="0.0.0.0/0",
                    gateway="203.0.113.1",
                    active=True,
                )
            ]
        )
        report = analyze_topology(snapshot)
        route_finding = next(
            f for f in report.findings if f.code == "active_default_route"
        )
        assert route_finding.status is CompatibilityCheckStatus.PASS

    def test_clean_topology_still_reports_bridge_inventory(self) -> None:
        snapshot = FakeSnapshot(
            bridges=[BridgeSnapshot(name="bridgeGuest", ports=["ether2"])],
            routes=[
                RouteSnapshot(
                    dst_address="0.0.0.0/0",
                    gateway="ether1",
                    active=True,
                )
            ],
        )
        report = analyze_topology(snapshot, wan_interfaces={"ether1"})
        assert any(f.code == "bridge_inventory" for f in report.findings)
        assert not any(f.code == "wan_in_bridge" for f in report.findings)

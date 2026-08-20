"""Unit tests for Wave 1 Step 8 guest interface availability (P10)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

from app.domains.isp.models import IspLink
from app.domains.provisioning_engine.planner.constants import (
    InterfaceAvailabilityStatus,
)
from app.domains.provisioning_engine.planner.exceptions import NoRouterSnapshotError
from app.domains.provisioning_engine.planner.guest_input import (
    evaluate_guest_interface_availability,
)
from app.domains.provisioning_engine.planner.guest_input_service import (
    GuestInputService,
)
from app.domains.provisioning_engine.planner.models import RouterSnapshot
from app.domains.provisioning_engine.planner.schemas import (
    BridgeSnapshot,
    DhcpServerSnapshot,
    InterfaceSnapshot,
)
from app.domains.router.models import Router
from tests.unit.test_isp import FakeRouterLookup, _base_fields, _make_router


@dataclass
class FakeSnapshot:
    interfaces: list[Any] = field(default_factory=list)
    bridges: list[Any] = field(default_factory=list)
    dhcp_clients: list[Any] = field(default_factory=list)
    dhcp_servers: list[Any] = field(default_factory=list)
    routes: list[Any] = field(default_factory=list)
    hotspot_state: dict[str, Any] = field(default_factory=dict)
    vlans: list[Any] = field(default_factory=list)


class TestEvaluateGuestInterfaceAvailability:
    def test_recommends_free_ether_port(self) -> None:
        snapshot = FakeSnapshot(
            interfaces=[
                InterfaceSnapshot(name="ether1", type="ether"),
                InterfaceSnapshot(name="ether2", type="ether"),
            ],
            routes=[
                {
                    "dst_address": "0.0.0.0/0",
                    "gateway": "ether1",
                    "active": True,
                }
            ],
        )
        report = evaluate_guest_interface_availability(
            snapshot, wan_interfaces={"ether1"}
        )
        ether2 = next(item for item in report.interfaces if item.name == "ether2")
        assert ether2.status is InterfaceAvailabilityStatus.RECOMMENDED
        assert report.recommendation.recommended_interfaces == ["ether2"]

    def test_marks_wan_ports(self) -> None:
        snapshot = FakeSnapshot(
            interfaces=[InterfaceSnapshot(name="ether1", type="ether")]
        )
        report = evaluate_guest_interface_availability(
            snapshot, wan_interfaces={"ether1"}
        )
        wan = next(item for item in report.interfaces if item.name == "ether1")
        assert wan.status is InterfaceAvailabilityStatus.WAN

    def test_marks_dhcp_server_interface_in_use(self) -> None:
        snapshot = FakeSnapshot(
            interfaces=[InterfaceSnapshot(name="ether2", type="ether")],
            dhcp_servers=[
                DhcpServerSnapshot(name="dhcp1", interface="ether2")
            ],
        )
        report = evaluate_guest_interface_availability(snapshot)
        ether2 = next(item for item in report.interfaces if item.name == "ether2")
        assert ether2.status is InterfaceAvailabilityStatus.IN_USE

    def test_prefers_existing_guest_bridge_member(self) -> None:
        snapshot = FakeSnapshot(
            interfaces=[
                InterfaceSnapshot(name="ether2", type="ether"),
                InterfaceSnapshot(name="ether3", type="ether"),
            ],
            bridges=[
                BridgeSnapshot(name="bridgeGuest", ports=["ether2"]),
            ],
        )
        report = evaluate_guest_interface_availability(snapshot)
        assert report.recommendation.recommended_interfaces == ["ether2"]
        assert report.recommendation.parent_bridge_hint == "bridgeGuest"


@dataclass
class FakeSnapshotRepository:
    latest: RouterSnapshot | None = None

    async def get_latest_for_router(
        self, router_id: uuid.UUID
    ) -> RouterSnapshot | None:
        if self.latest is None or self.latest.router_id != router_id:
            return None
        return self.latest


@dataclass
class FakeIspLinkLookup:
    links: list[IspLink]

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        values = list(self.links)
        if router_id is not None:
            values = [link for link in values if link.router_id == router_id]
        return values, object()


def _make_snapshot_row(router: Router) -> RouterSnapshot:
    return RouterSnapshot(
        **_base_fields(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            captured_at=datetime.now(UTC),
            trigger="wizard_discovery",
            status="complete",
            interfaces=[
                {"name": "ether1", "type": "ether"},
                {"name": "ether2", "type": "ether"},
            ],
            bridges=[],
            ip_addresses=[],
            dhcp_clients=[],
            dhcp_servers=[],
            routes=[],
            dns_config={},
            firewall_summary={},
            nat_summary={},
            hotspot_state={},
            vlans=[],
            services=[],
            packages=[],
            error_detail=None,
        )
    )


def _make_isp_link(router: Router, **fields: object) -> IspLink:
    base = {
        "router_id": router.id,
        "organization_id": router.organization_id,
        "location_id": router.location_id,
        "provider_name": "Airtel",
        "link_type": "fiber",
        "connection_mode": "dhcp",
        "role": "primary",
        "is_active_uplink": True,
        "auto_failback": True,
        "is_enabled": True,
        "priority": 0,
        "interface": "ether1",
        "physical_interface": "ether1",
        "routing_interface": "ether1",
        "gateway_ip_address": None,
        "dns_primary": None,
        "dns_secondary": None,
        "download_bandwidth_mbps": None,
        "upload_bandwidth_mbps": None,
        "health_status": "unknown",
        "health_status_source": "automated",
        "latency_ms": None,
        "packet_loss_percentage": None,
        "last_checked_at": None,
        "consecutive_unhealthy_count": 0,
    }
    base.update(fields)
    return IspLink(**_base_fields(**base))


@pytest.mark.asyncio
async def test_guest_input_service_uses_snapshot_and_isp_links() -> None:
    router = _make_router()
    snapshot = _make_snapshot_row(router)
    router_lookup = FakeRouterLookup()
    router_lookup.add(router)
    service = GuestInputService(
        repository=FakeSnapshotRepository(latest=snapshot),
        router_lookup=router_lookup,
        isp_link_lookup=FakeIspLinkLookup(links=[_make_isp_link(router)]),
    )

    result = await service.get_interface_availability(
        router.id, requesting_organization_id=None
    )

    assert result.snapshot_id == str(snapshot.id)
    assert result.recommendation.recommended_interfaces == ["ether2"]


@pytest.mark.asyncio
async def test_guest_input_service_requires_snapshot() -> None:
    router = _make_router()
    router_lookup = FakeRouterLookup()
    router_lookup.add(router)
    service = GuestInputService(
        repository=FakeSnapshotRepository(latest=None),
        router_lookup=router_lookup,
        isp_link_lookup=FakeIspLinkLookup(links=[]),
    )
    with pytest.raises(NoRouterSnapshotError):
        await service.get_interface_availability(
            router.id, requesting_organization_id=None
        )

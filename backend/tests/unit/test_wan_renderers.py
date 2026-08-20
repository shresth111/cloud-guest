"""Unit tests for server-side basic WAN profile renderers."""

from __future__ import annotations

import uuid

import pytest

from app.domains.isp.constants import IspConnectionMode, IspLinkRole, WanRoutingMode
from app.domains.isp.models import IspLink
from app.domains.network_config.exceptions import MissingStaticWanAddressError
from app.domains.network_config.wan import render_basic_wan_config
from app.domains.network_config.wan.build_context import build_wan_render_context
from app.domains.network_config.wan.context import WanRenderContext, WanRenderLink
from app.domains.network_config.wan.pcc import build_weighted_pcc_plan
from app.domains.router.models import Router


def _make_router(**kwargs: object) -> Router:
    base = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "r1",
        "serial_number": "SN1",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "model": "RB4011",
        "vendor": "mikrotik",
        "status": "online",
        "wan_routing_mode": "load_balance",
    }
    base.update(kwargs)
    return Router(**base)


def _make_link(**kwargs: object) -> IspLink:
    base = {
        "id": uuid.uuid4(),
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "provider_name": "ISP",
        "link_type": "fiber",
        "connection_mode": IspConnectionMode.DHCP.value,
        "role": IspLinkRole.PRIMARY.value,
        "is_active_uplink": True,
        "auto_failback": True,
        "is_enabled": True,
        "priority": 0,
        "physical_interface": "ether1",
        "routing_interface": "ether1",
        "interface": "ether1",
        "health_status": "unknown",
        "health_status_source": "automated",
        "consecutive_unhealthy_count": 0,
    }
    base.update(kwargs)
    return IspLink(**base)


def test_build_weighted_pcc_plan_gcd_reduction() -> None:
    plan = build_weighted_pcc_plan([70, 30])
    assert plan is not None
    assert plan.total == 10
    assert len(plan.indices_by_wan[0]) == 7
    assert len(plan.indices_by_wan[1]) == 3


def test_render_dhcp_wan_includes_client_and_nat() -> None:
    ctx = WanRenderContext(
        links=[
            WanRenderLink(
                link_id=uuid.uuid4(),
                slot=1,
                connection_mode=IspConnectionMode.DHCP,
                physical_interface="ether1",
                effective_interface="ether1",
            )
        ]
    )
    script = render_basic_wan_config(ctx)
    assert "cloudguest-dhcp-wan1" in script
    assert "cloudguest-nat-wan1" in script
    assert "/interface list add name=\"WAN\"" in script


def test_render_pppoe_wan_uses_virtual_interface() -> None:
    ctx = WanRenderContext(
        links=[
            WanRenderLink(
                link_id=uuid.uuid4(),
                slot=1,
                connection_mode=IspConnectionMode.PPPOE,
                physical_interface="ether1",
                effective_interface="cloudguest-pppoe-wan1",
                pppoe_username="user@isp",
                pppoe_password="secret",
            )
        ]
    )
    script = render_basic_wan_config(ctx)
    assert "cloudguest-pppoe-wan1" in script
    assert 'user="user@isp"' in script
    assert "pppoe-client monitor" in script


def test_render_dual_wan_load_balance_includes_mangle() -> None:
    ctx = WanRenderContext(
        links=[
            WanRenderLink(
                link_id=uuid.uuid4(),
                slot=1,
                connection_mode=IspConnectionMode.DHCP,
                physical_interface="ether1",
                effective_interface="ether1",
            ),
            WanRenderLink(
                link_id=uuid.uuid4(),
                slot=2,
                connection_mode=IspConnectionMode.DHCP,
                physical_interface="ether2",
                effective_interface="ether2",
            ),
        ],
        wan_routing_mode=WanRoutingMode.LOAD_BALANCE,
        lan_bridge="bridge1",
    )
    script = render_basic_wan_config(ctx)
    assert "cloudguest-route-wan1" in script
    assert "cloudguest-mangle-pcc-wan1" in script
    assert "to_wan2" in script


def test_static_link_requires_address_override() -> None:
    router = _make_router()
    link = _make_link(
        connection_mode=IspConnectionMode.STATIC.value,
        gateway_ip_address="203.0.113.1",
    )
    with pytest.raises(MissingStaticWanAddressError):
        build_wan_render_context(router=router, links=[link])

    ctx = build_wan_render_context(
        router=router,
        links=[link],
        static_addresses={link.id: "203.0.113.5/24"},
    )
    assert ctx.links[0].static_address == "203.0.113.5/24"

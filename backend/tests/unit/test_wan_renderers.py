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


class TestWanGatewayRaceGuard:
    """Regression tests for the 2026-08-21 ``/import`` DHCP race.

    The WAN script adds a ``/ip dhcp-client`` and reads its ``gateway`` a
    few lines later. Pasted chunk by chunk that gap is seconds and the
    lease has bound; under ``/import`` it is microseconds and it has not,
    so the read yielded ``0.0.0.0`` and the old ``!= ""`` guard let it
    through into a real ``/ip route``, which RouterOS accepts and flags
    ``Is`` (Inactive) -- "no route to host" on every ping, silently.
    """

    @staticmethod
    def _dhcp_script(interface: str = "ether1") -> str:
        return render_basic_wan_config(
            WanRenderContext(
                links=[
                    WanRenderLink(
                        link_id=uuid.uuid4(),
                        slot=1,
                        connection_mode=IspConnectionMode.DHCP,
                        physical_interface=interface,
                        effective_interface=interface,
                    )
                ]
            )
        )

    def test_dhcp_gateway_read_is_retried_not_read_once(self) -> None:
        script = self._dhcp_script()
        assert ":for wan1Try from=1 to=30 do={" in script
        assert ":delay 1s" in script

    def test_zero_gateway_is_rejected(self) -> None:
        script = self._dhcp_script()
        assert '$wan1Gw != "0.0.0.0"' in script

    def test_unresolved_gateway_aborts_the_import(self) -> None:
        """``:put``/``:log`` do not stop ``/import`` -- only ``:error``."""
        script = self._dhcp_script()
        abort = next(
            line for line in script.splitlines() if "never obtained a usable" in line
        )
        assert abort.lstrip().startswith(":if (!$wan1Ok) do={ :error ")

    def test_routes_are_gated_on_the_validated_flag(self) -> None:
        script = self._dhcp_script()
        assert ":if ($wan1Ok) do={" in script
        assert ':if ($wan1Gw != "") do={' not in script

    def test_pppoe_gateway_waits_and_aborts_too(self) -> None:
        """Same defect class, same fix -- PPPoE previously only warned."""
        script = render_basic_wan_config(
            WanRenderContext(
                links=[
                    WanRenderLink(
                        link_id=uuid.uuid4(),
                        slot=1,
                        connection_mode=IspConnectionMode.PPPOE,
                        physical_interface="ether1",
                        effective_interface="cloudguest-pppoe-wan1",
                        pppoe_username="u",
                        pppoe_password="p",
                    )
                ]
            )
        )
        assert ":for wan1Try from=1 to=30 do={" in script
        assert "never obtained a usable gateway" in script
        assert "gateway not resolved yet" not in script

    def test_static_link_without_gateway_aborts(self) -> None:
        script = render_basic_wan_config(
            WanRenderContext(
                links=[
                    WanRenderLink(
                        link_id=uuid.uuid4(),
                        slot=1,
                        connection_mode=IspConnectionMode.STATIC,
                        physical_interface="ether1",
                        effective_interface="ether1",
                        static_address="10.0.0.2/24",
                        gateway=None,
                    )
                ]
            )
        )
        assert "is configured STATIC but has no gateway" in script

    def test_each_link_gets_its_own_wait_loop(self) -> None:
        script = render_basic_wan_config(
            WanRenderContext(
                links=[
                    WanRenderLink(
                        link_id=uuid.uuid4(),
                        slot=n,
                        connection_mode=IspConnectionMode.DHCP,
                        physical_interface=f"ether{n}",
                        effective_interface=f"ether{n}",
                    )
                    for n in (1, 2)
                ],
                wan_routing_mode=WanRoutingMode.LOAD_BALANCE,
            )
        )
        for n in (1, 2):
            assert f":for wan{n}Try from=1 to=30 do={{" in script
            assert f":if (!$wan{n}Ok) do={{ :error " in script

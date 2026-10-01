""" "Guests can't see each other": the per-router switch, end to end through
the real firewall adapter and the vendored gateway, against the gateway's
own write-capable fake RouterOS API (a hEX lite: ether1 WAN, ether2-5 in
``bridge``, hotspot on ``bridge``, access points on ether2 and ether3).

Pinned here:

* on puts the guest ports in the platform's horizon group, never ether1
  (WAN) and never the bridge itself; off restores every port exactly;
* the status is honest: "isolated between ports: yes, 2 AP ports found;
  same-AP isolation must be set on your access points";
* the gates every firewall write has: Omada refused, cross-site refused,
  the router's forward-chain lock taken, an audit row written;
* a refusal (VLAN-filtering bridge) is a 409 with its code and no write.

The gateway's own ordering/exclusion/restore tests live in
``vendor/wyfy-device-gateway/tests/test_mikrotik_guest_isolation.py``.
Nothing here touches a real router.
"""

from __future__ import annotations

import copy
import uuid
from typing import Any

import pytest

from app.domains.firewall import service as firewall_service_module
from app.domains.firewall.exceptions import (
    CrossLocationFirewallRuleAccessError,
    FirewallPushRefusedError,
)
from app.domains.firewall.router import router as firewall_router
from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
)

from .test_firewall_device_push import (
    _gateway_fake_api_module,
    _harness,
    _lab_filter,
    _permission_of,
    _router,
)

_PORT = ("interface", "bridge", "port")
_HORIZON = "7319"


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch):
    import wyfy_device_gateway.mikrotik_adapter as gateway

    fake_module = _gateway_fake_api_module()

    class _Api(fake_module.FakeRouterOSApi):
        _n = 700

        def mint_id(self, row_count: int) -> str:
            type(self)._n += 1
            return f"*N{self._n}"

    def install(*, band: bool = True, vlan_filtering: bool = False):
        api = _Api(
            menus={
                ("ip", "firewall", "filter"): _lab_filter(band=band),
                ("interface",): [
                    {"name": "ether1", "type": "ether", "running": "true"},
                    {"name": "ether2", "type": "ether", "running": "true"},
                    {"name": "ether3", "type": "ether", "running": "true"},
                    {"name": "ether4", "type": "ether", "running": "false"},
                    {"name": "ether5", "type": "ether", "running": "false"},
                    {"name": "bridge", "type": "bridge", "running": "true"},
                ],
                ("interface", "bridge"): [
                    {
                        "name": "bridge",
                        "vlan-filtering": "true" if vlan_filtering else "false",
                    }
                ],
                _PORT: [
                    {
                        ".id": f"*P{n}",
                        "bridge": "bridge",
                        "interface": f"ether{n}",
                        "horizon": "none",
                        "comment": "defconf",
                    }
                    for n in (2, 3, 4, 5)
                ],
                ("ip", "address"): [
                    {".id": "*A1", "address": "192.168.88.1/24", "interface": "bridge"}
                ],
                ("ip", "dhcp-client"): [{".id": "*DC", "interface": "ether1"}],
                ("ip", "hotspot"): [
                    {".id": "*H", "name": "hs1", "interface": "bridge"}
                ],
            }
        )
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        return api

    return install


def _horizons(api: Any) -> dict[str, str]:
    return {r["interface"]: r["horizon"] for r in api.path(*_PORT)}


async def _set(h, router, enabled: bool):
    return await h.service.set_guest_isolation(
        router.id,
        enabled=enabled,
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
    )


class TestSwitch:
    async def test_on_isolates_the_guest_ports_and_says_so_honestly(
        self, device
    ) -> None:
        api = device()
        h = _harness()
        router = h.routers.add(_router())

        state = await _set(h, router, True)

        assert _horizons(api) == {f"ether{n}": _HORIZON for n in (2, 3, 4, 5)}
        assert state.enabled and state.consistent and state.between_ports
        assert state.routed_guard
        assert state.guest_ports == 4 and state.isolated_ports == 4
        assert state.ap_ports == 2  # ether2 and ether3 have a link
        assert state.ap_isolation_needed
        assert state.radios_isolated is None  # a hEX lite has no radio
        assert state.summary == (
            "Isolated between ports: yes, 2 AP ports found; same-AP isolation "
            "must be set on your access points."
        )

    async def test_off_restores_the_router_exactly(self, device) -> None:
        api = device()
        before = copy.deepcopy(
            {
                k: [dict(r) for r in api.path(*k)]
                for k in (_PORT, ("ip", "firewall", "filter"))
            }
        )
        h = _harness()
        router = h.routers.add(_router())
        await _set(h, router, True)

        state = await _set(h, router, False)

        for key, rows in before.items():
            assert [dict(r) for r in api.path(*key)] == rows
        assert not state.enabled and not state.between_ports
        assert state.summary.startswith("Isolated between ports: no, 2 AP ports found")

    async def test_the_state_is_read_off_the_router(self, device) -> None:
        api = device()
        h = _harness()
        router = h.routers.add(_router())
        await _set(h, router, True)
        for row in api.path(*_PORT):
            row["horizon"] = "none"  # the router was reset by hand
        state = await h.service.read_guest_isolation(
            router.id, requesting_organization_id=router.organization_id
        )
        assert not state.between_ports
        assert state.enabled and not state.consistent  # guard row still there

    async def test_without_a_band_it_still_isolates_the_ports(self, device) -> None:
        device(band=False)
        h = _harness()
        router = h.routers.add(_router())
        state = await _set(h, router, True)
        assert state.between_ports and not state.routed_guard
        assert state.band_state == "missing"

    async def test_vlan_filtering_is_a_409_and_no_write(self, device) -> None:
        api = device(vlan_filtering=True)
        h = _harness()
        router = h.routers.add(_router())
        with pytest.raises(FirewallPushRefusedError) as info:
            await _set(h, router, True)
        assert info.value.data["code"] == "ISOLATION_VLAN_BRIDGE"
        assert [op for op in api.ops if op[0] != "command"] == []
        state = await h.service.read_guest_isolation(
            router.id, requesting_organization_id=router.organization_id
        )
        assert state.refusal == "ISOLATION_VLAN_BRIDGE"

    async def test_a_change_is_audited(self, device) -> None:
        device()
        h = _harness()
        router = h.routers.add(_router())
        await _set(h, router, True)
        actions = [e["action"] for e in h.audit.entries]
        assert actions == [AuditAction.FIREWALL_GUEST_ISOLATION_CHANGED.value]
        assert "turned on" in str(h.audit.entries[0]["description"])


class TestGates:
    async def test_controller_managed_router_is_refused_before_any_socket(
        self, device
    ) -> None:
        api = device()
        h = _harness()
        router = h.routers.add(_router(vendor="tplink_omada"))
        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await _set(h, router, True)
        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await h.service.read_guest_isolation(
                router.id, requesting_organization_id=router.organization_id
            )
        assert api.ops == []

    async def test_a_caller_confined_to_another_site_is_refused(self, device) -> None:
        api = device()
        h = _harness(scope=frozenset({uuid.uuid4()}))
        router = h.routers.add(_router())
        with pytest.raises(CrossLocationFirewallRuleAccessError):
            await _set(h, router, True)
        assert api.ops == []

    async def test_the_write_takes_the_router_firewall_lock(
        self, device, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        device()
        h = _harness()
        router = h.routers.add(_router())
        taken: list[uuid.UUID] = []
        original = firewall_service_module.FirewallService._router_lock

        def spy(self, router_id):  # noqa: ANN001, ANN202
            taken.append(router_id)
            return original(self, router_id)

        monkeypatch.setattr(
            firewall_service_module.FirewallService, "_router_lock", spy
        )
        await _set(h, router, True)
        await _set(h, router, False)
        assert taken == [router.id, router.id]

    def test_routes_are_router_scoped(self) -> None:
        found = {}
        for route in firewall_router.routes:
            if route.path.endswith("/routers/{router_id}/guest-isolation"):
                for method in route.methods:
                    found[method] = _permission_of(route)[0]
        assert set(found) == {"GET", "PUT"}
        assert "firewall.read" in found["GET"] and ScopeType.ROUTER in found["GET"]
        assert "firewall.execute" in found["PUT"] and ScopeType.ROUTER in found["PUT"]

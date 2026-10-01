""" "Limit connection floods": the per-router switch, end to end through the
real firewall adapter and the vendored gateway, against the gateway's own
write-capable fake RouterOS API.

Pinned here:

* each preset writes its cap (300/150/80) as ``connection-limit=<N>,32`` on
  ``chain=forward``, one row per guest network, at the top of the band;
* ``off`` removes exactly those rows and nothing else;
* the state is read back off the router, never remembered;
* the gates every firewall write has: Omada refused, cross-site refused,
  the router's forward-chain lock taken, an audit row written;
* no band -> 409 with ``ACCESS_RULES_BAND_MISSING`` and no write.

The gateway's own ordering/idempotency/refusal tests live in
``vendor/wyfy-device-gateway/tests/test_mikrotik_flood_limit.py``. Nothing
here touches a real router.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.domains.firewall import service as firewall_service_module
from app.domains.firewall.constants import FLOOD_LIMIT_PRESETS, FloodLimitPreset
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

_FLOOD = "cloudguest-fw-flood-limit"


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch):
    import wyfy_device_gateway.mikrotik_adapter as gateway

    fake_module = _gateway_fake_api_module()

    class _Api(fake_module.FakeRouterOSApi):
        _n = 500

        def mint_id(self, row_count: int) -> str:
            type(self)._n += 1
            return f"*N{self._n}"

    def install(*, band: bool = True):
        api = _Api(
            menus={
                ("ip", "firewall", "filter"): _lab_filter(band=band),
                ("ip", "address"): [
                    {
                        ".id": "*A1",
                        "address": "10.5.50.1/24",
                        "interface": "bridge-guest",
                    },
                    {
                        ".id": "*A2",
                        "address": "192.168.88.1/24",
                        "interface": "bridge-office",
                    },
                ],
                ("ip", "hotspot"): [
                    {".id": "*H", "name": "hs1", "interface": "bridge-guest"}
                ],
            }
        )
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        return api

    return install


def _flood_rows(api: Any) -> list[dict[str, Any]]:
    return [
        r for r in api.path("ip", "firewall", "filter") if r.get("comment") == _FLOOD
    ]


async def _set(h, router, preset: FloodLimitPreset):
    return await h.service.set_flood_limit(
        router.id,
        preset=preset,
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
    )


class TestSwitch:
    @pytest.mark.parametrize(
        ("preset", "cap"),
        [
            (FloodLimitPreset.RELAXED, 300),
            (FloodLimitPreset.NORMAL, 150),
            (FloodLimitPreset.STRICT, 80),
        ],
    )
    async def test_each_preset_writes_its_cap_on_the_guest_network_only(
        self, device, preset, cap
    ) -> None:
        api = device()
        h = _harness()
        router = h.routers.add(_router())

        state = await _set(h, router, preset)

        rows = _flood_rows(api)
        assert len(rows) == 1
        row = rows[0]
        assert row["chain"] == "forward"
        assert row["action"] == "drop"
        assert row["protocol"] == "tcp"
        assert row["connection-state"] == "new"
        assert row["connection-limit"] == f"{cap},32"
        # The guest network, never the office network beside it.
        assert row["src-address"] == "10.5.50.0/24"
        assert state.preset is preset and state.limit == cap
        assert state.enabled and state.consistent
        assert FLOOD_LIMIT_PRESETS[preset] == cap

    async def test_off_takes_exactly_our_rows_off(self, device) -> None:
        api = device()
        before = [dict(r) for r in api.path("ip", "firewall", "filter")]
        h = _harness()
        router = h.routers.add(_router())
        await _set(h, router, FloodLimitPreset.NORMAL)

        state = await _set(h, router, FloodLimitPreset.OFF)

        assert _flood_rows(api) == []
        assert list(api.path("ip", "firewall", "filter")) == before
        assert state.preset is FloodLimitPreset.OFF and not state.enabled

    async def test_the_state_is_read_off_the_router(self, device) -> None:
        api = device()
        h = _harness()
        router = h.routers.add(_router())
        await _set(h, router, FloodLimitPreset.STRICT)
        # Someone resets the router: the screen must say off, not "strict".
        for row in _flood_rows(api):
            api.path("ip", "firewall", "filter").remove(row[".id"])

        state = await h.service.read_flood_limit(
            router.id, requesting_organization_id=router.organization_id
        )
        assert state.preset is FloodLimitPreset.OFF and not state.enabled
        assert state.band_state == "ready"
        assert state.guest_networks == ("10.5.50.0/24",)

    async def test_no_band_is_a_409_and_no_write(self, device) -> None:
        api = device(band=False)
        h = _harness()
        router = h.routers.add(_router())
        with pytest.raises(FirewallPushRefusedError) as info:
            await _set(h, router, FloodLimitPreset.NORMAL)
        assert info.value.data["code"] == "ACCESS_RULES_BAND_MISSING"
        assert [op for op in api.ops if op[0] != "command"] == []

    async def test_a_change_is_audited(self, device) -> None:
        device()
        h = _harness()
        router = h.routers.add(_router())
        await _set(h, router, FloodLimitPreset.RELAXED)
        actions = [e["action"] for e in h.audit.entries]
        assert actions == [AuditAction.FIREWALL_FLOOD_LIMIT_CHANGED.value]
        assert "relaxed" in str(h.audit.entries[0]["description"])


class TestGates:
    async def test_controller_managed_router_is_refused_before_any_socket(
        self, device
    ) -> None:
        api = device()
        h = _harness()
        router = h.routers.add(_router(vendor="tplink_omada"))
        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await _set(h, router, FloodLimitPreset.NORMAL)
        assert api.ops == []

    async def test_a_caller_confined_to_another_site_is_refused(self, device) -> None:
        api = device()
        h = _harness(scope=frozenset({uuid.uuid4()}))
        router = h.routers.add(_router())
        with pytest.raises(CrossLocationFirewallRuleAccessError):
            await _set(h, router, FloodLimitPreset.NORMAL)
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
        await _set(h, router, FloodLimitPreset.NORMAL)
        assert taken == [router.id]

    def test_routes_are_router_scoped(self) -> None:
        """Read is ``firewall.read``, write is ``firewall.execute`` -- the push's
        own grant, since it writes the same chain -- both pinned to ROUTER."""
        found = {}
        for route in firewall_router.routes:
            if route.path.endswith("/routers/{router_id}/flood-limit"):
                for method in route.methods:
                    found[method] = _permission_of(route)[0]
        assert set(found) == {"GET", "PUT"}
        assert "firewall.read" in found["GET"] and ScopeType.ROUTER in found["GET"]
        assert "firewall.execute" in found["PUT"] and ScopeType.ROUTER in found["PUT"]

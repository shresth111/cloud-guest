"""Guest isolation ("guests can't see each other"), against a fake RouterOS API.

What these pin, and why each matters on a real router:

* **Only guest ports, never the uplink or the CPU port.** The horizon goes on
  the hotspot bridge's physical member ports; the WAN (DHCP client, PPPoE,
  default route, WAN list), a port with a VLAN or an address on it, and the
  bridge interface itself are never written.
* **Exact restore.** Off returns exactly the ports carrying this platform's
  horizon to ``none``, puts each radio back to its RECORDED previous value,
  removes the guard rows and the record, and leaves every other row as it was.
* **Refuse rather than guess.** VLAN filtering, a hotspot on a VLAN, a
  hand-set horizon, no hotspot, nothing to isolate: refused, nothing written.
* **Ports last; undo on failure.** The (switch-resetting) port writes come
  after everything else; a failure part-way puts back what was written.
* **Read back.** A write the router silently ignores fails, not "success".

Nothing in this file has been run against hardware; see
``~/wyfy-ops/cftest/isotest.py`` for the device check.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikFirewallPushFailedError,
    MikroTikFirewallRefusedError,
)
from wyfy_device_gateway.mikrotik_firewall import FirewallPushFailed, FirewallRefusal
from wyfy_device_gateway.mikrotik_guest_isolation import (
    GUARD_COMMENT,
    ISOLATION_BRIDGE_CARRIES_WAN,
    ISOLATION_HORIZON,
    ISOLATION_HORIZON_IN_USE,
    ISOLATION_NO_HOTSPOT,
    ISOLATION_NOTHING_TO_ISOLATE,
    ISOLATION_VLAN_BRIDGE,
    RECORD_LIST,
    apply_guest_isolation,
    read_guest_isolation,
    remove_guest_isolation,
)

_PORT = ("interface", "bridge", "port")
_FILTER = ("ip", "firewall", "filter")
H = str(ISOLATION_HORIZON)


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


def _forward(*, band: bool = True) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {".id": "*D1", "chain": "forward", "action": "jump", "jump-target": "hs-unauth",
         "hotspot": "from-client,!auth", "dynamic": True},
    ]
    if band:
        rows += [
            {".id": "*BB", "chain": "forward", "action": "passthrough",
             "comment": "cloudguest-fw-band-begin"},
            {".id": "*C1", "chain": "forward", "action": "accept",
             "src-address": "192.168.88.10",
             "comment": "cloudguest-fw:11111111-1111-1111-1111-111111111111"},
            {".id": "*BE", "chain": "forward", "action": "passthrough",
             "comment": "cloudguest-fw-band-end"},
        ]
    rows.append({".id": "*E", "chain": "forward", "action": "accept",
                 "connection-state": "established,related",
                 "comment": "cloudguest-fw-fwd-established"})
    rows.append({".id": "*I1", "chain": "input", "action": "accept", "protocol": "udp",
                 "in-interface": "wg-cloudguard", "comment": "cloudguest-fw-allow-wg-mgmt"})
    return rows


def _hex_lite(
    overrides: dict[tuple[str, ...], list[dict[str, Any]]] | None = None,
    *,
    band: bool = True,
) -> _Api:
    """The lab hEX lite: ether1 WAN (DHCP client), ether2-5 in ``bridge``
    with the hotspot on it; APs on ether2 and ether3."""
    menus: dict[tuple[str, ...], list[dict[str, Any]]] = {
        ("interface",): [
            {"name": "ether1", "type": "ether", "running": "true"},
            {"name": "ether2", "type": "ether", "running": "true"},
            {"name": "ether3", "type": "ether", "running": "true"},
            {"name": "ether4", "type": "ether", "running": "false"},
            {"name": "ether5", "type": "ether", "running": "false"},
            {"name": "bridge", "type": "bridge", "running": "true"},
            {"name": "wg-cloudguard", "type": "wg", "running": "true"},
        ],
        ("interface", "bridge"): [{".id": "*B", "name": "bridge", "vlan-filtering": "false"}],
        _PORT: [
            {".id": f"*P{n}", "bridge": "bridge", "interface": f"ether{n}",
             "horizon": "none", "hw": "true", "hw-offload": "true", "comment": "defconf"}
            for n in (2, 3, 4, 5)
        ],
        ("ip", "address"): [
            {".id": "*A1", "address": "192.168.88.1/24", "interface": "bridge"},
            {".id": "*A2", "address": "10.100.0.7/24", "interface": "wg-cloudguard"},
        ],
        ("ip", "dhcp-client"): [{".id": "*DC", "interface": "ether1"}],
        ("ip", "route"): [{".id": "*R", "dst-address": "0.0.0.0/0",
                           "gateway": "203.0.113.1", "immediate-gw": "203.0.113.1%ether1"}],
        ("ip", "hotspot"): [{".id": "*H", "name": "hs1", "interface": "bridge"}],
        _FILTER: _forward(band=band),
    }
    menus.update(overrides or {})
    return _Api(menus=menus)


def _ports(api: _Api) -> dict[str, str]:
    return {r["interface"]: r["horizon"] for r in api.path(*_PORT)}


def _guard(api: _Api) -> list[dict[str, Any]]:
    return [r for r in api.path(*_FILTER) if r.get("comment") == GUARD_COMMENT]


def _dump(api: _Api) -> dict[tuple[str, ...], list[dict[str, Any]]]:
    return copy.deepcopy({k: list(v) for k, v in api._menus.items()})


class TestApply:
    def test_puts_every_guest_port_in_one_horizon_group_and_nothing_else(self) -> None:
        api = _hex_lite()
        result = apply_guest_isolation(api)
        assert _ports(api) == {"ether2": H, "ether3": H, "ether4": H, "ether5": H}
        assert sorted(result.ports_changed) == ["ether2", "ether3", "ether4", "ether5"]
        # Never the WAN, never the bridge (CPU port), never input.
        written = {op[1] for op in api.ops}
        assert written <= {_PORT, _FILTER}
        for op in api.ops:
            if op[1] == _PORT:
                assert op[2][".id"] in {"*P2", "*P3", "*P4", "*P5"}
            if op[0] == "add" and op[1] == _FILTER:
                assert op[2]["chain"] == "forward"

    def test_ports_are_written_last(self) -> None:
        api = _hex_lite()
        apply_guest_isolation(api)
        kinds = [op[1] for op in api.ops]
        first_port = kinds.index(_PORT)
        assert all(k == _PORT for k in kinds[first_port:])

    def test_guard_row_at_the_top_of_the_band_above_customer_rules(self) -> None:
        api = _hex_lite()
        apply_guest_isolation(api)
        rows = _guard(api)
        assert len(rows) == 1
        assert rows[0]["src-address"] == "192.168.88.0/24"
        assert rows[0]["dst-address"] == "192.168.88.0/24"
        assert rows[0]["action"] == "drop"
        order = [r[".id"] for r in api.path(*_FILTER)]
        assert order.index("*BB") < order.index(rows[0][".id"]) < order.index("*C1")

    def test_without_a_band_the_ports_are_still_isolated_and_no_row_is_written(self) -> None:
        api = _hex_lite(band=False)
        apply_guest_isolation(api)
        assert set(_ports(api).values()) == {H}
        assert _guard(api) == []
        status = read_guest_isolation(api)
        assert status.between_ports and not status.routed_guard
        assert status.band_state == "missing"
        assert status.consistent

    def test_is_idempotent(self) -> None:
        api = _hex_lite()
        apply_guest_isolation(api)
        n = len(api.ops)
        result = apply_guest_isolation(api)
        assert len(api.ops) == n
        assert result.ports_changed == () and result.guard_rows_added == 0

    def test_a_new_port_is_reported_and_picked_up_on_reapply(self) -> None:
        api = _hex_lite()
        apply_guest_isolation(api)
        api.path(*_PORT).remove("*P5")
        api._menus[_PORT].append(
            {".id": "*P5b", "bridge": "bridge", "interface": "ether5", "horizon": "none"}
        )
        status = read_guest_isolation(api)
        assert status.enabled and not status.consistent and not status.between_ports
        apply_guest_isolation(api)
        assert read_guest_isolation(api).consistent

    def test_a_silently_ignored_port_write_fails_and_is_undone(self) -> None:
        api = _hex_lite()
        api.silently_ignore_updates.add(_PORT)
        with pytest.raises(FirewallPushFailed) as info:
            apply_guest_isolation(api)
        assert info.value.restored is True
        assert _guard(api) == []  # the guard row added earlier was taken off

    def test_a_failure_mid_ports_undoes_the_ports_already_written(self) -> None:
        api = _hex_lite()
        before = _dump(api)
        real = api.path

        class _Boom:
            def __init__(self, inner):  # noqa: ANN001
                self._inner = inner

            def __iter__(self):
                return iter(self._inner)

            def update(self, **fields: Any) -> None:
                if fields.get(".id") == "*P4" and fields.get("horizon") == H:
                    raise RuntimeError("connection reset")
                self._inner.update(**fields)

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        api.path = lambda *s: _Boom(real(*s)) if s == _PORT else real(*s)  # type: ignore[method-assign]
        with pytest.raises(FirewallPushFailed) as info:
            apply_guest_isolation(api)
        assert info.value.restored is True
        api.path = real  # type: ignore[method-assign]
        assert _ports(api) == {f"ether{n}": "none" for n in (2, 3, 4, 5)}
        assert [dict(r) for r in api.path(*_FILTER)] == before[_FILTER]


class TestExclusions:
    def test_wan_inside_the_bridge_is_never_isolated(self) -> None:
        ports = [
            {".id": f"*P{n}", "bridge": "bridge", "interface": f"ether{n}", "horizon": "none"}
            for n in (2, 3, 4)
        ]
        api = _hex_lite({
            _PORT: ports,
            ("interface", "list", "member"): [{".id": "*M", "list": "WAN", "interface": "ether4"}],
        })
        apply_guest_isolation(api)
        assert _ports(api) == {"ether2": H, "ether3": H, "ether4": "none"}
        status = read_guest_isolation(api)
        reasons = {p.interface: p.excluded_reason for p in status.ports}
        assert reasons["ether4"] == "wan"

    def test_a_port_carrying_a_vlan_or_an_address_is_left_alone(self) -> None:
        api = _hex_lite({
            ("interface", "vlan"): [{"name": "vlan-ap-mgmt", "interface": "ether4", "vlan-id": "99"}],
            ("ip", "address"): [
                {".id": "*A1", "address": "192.168.88.1/24", "interface": "bridge"},
                {".id": "*A9", "address": "10.9.9.1/24", "interface": "ether5"},
            ],
        })
        apply_guest_isolation(api)
        assert _ports(api) == {"ether2": H, "ether3": H, "ether4": "none", "ether5": "none"}

    def test_pppoe_parent_and_default_route_interface_are_wan(self) -> None:
        api = _hex_lite({
            ("ip", "dhcp-client"): [],
            ("interface", "pppoe-client"): [{"name": "pppoe-out1", "interface": "ether5"}],
            ("ip", "route"): [{"dst-address": "0.0.0.0/0", "gateway": "ether4"}],
        })
        apply_guest_isolation(api)
        assert _ports(api)["ether4"] == "none"
        assert _ports(api)["ether5"] == "none"


class TestRefusals:
    def _refused(self, api: _Api, code: str) -> None:
        with pytest.raises(FirewallRefusal) as info:
            apply_guest_isolation(api)
        assert info.value.code == code
        assert api.ops == []
        assert read_guest_isolation(api).refusal == code

    def test_vlan_filtering_bridge(self) -> None:
        self._refused(
            _hex_lite({("interface", "bridge"): [{"name": "bridge", "vlan-filtering": "true"}]}),
            ISOLATION_VLAN_BRIDGE,
        )

    def test_hotspot_on_a_vlan_of_a_bridge(self) -> None:
        self._refused(
            _hex_lite({
                ("interface", "vlan"): [{"name": "vlan20", "interface": "bridge", "vlan-id": "20"}],
                ("ip", "hotspot"): [{".id": "*H", "interface": "vlan20"}],
            }),
            ISOLATION_VLAN_BRIDGE,
        )

    def test_a_hand_set_horizon(self) -> None:
        api = _hex_lite()
        api._menus[_PORT][1]["horizon"] = "1"
        self._refused(api, ISOLATION_HORIZON_IN_USE)

    def test_no_hotspot(self) -> None:
        self._refused(_hex_lite({("ip", "hotspot"): []}), ISOLATION_NO_HOTSPOT)

    def test_bridge_carrying_the_uplink(self) -> None:
        self._refused(
            _hex_lite({("ip", "dhcp-client"): [{"interface": "bridge"}]}),
            ISOLATION_BRIDGE_CARRIES_WAN,
        )

    def test_one_port_and_no_radio(self) -> None:
        self._refused(
            _hex_lite({_PORT: [{".id": "*P2", "bridge": "bridge", "interface": "ether2",
                                  "horizon": "none"}]}),
            ISOLATION_NOTHING_TO_ISOLATE,
        )


class TestRemove:
    def test_restores_the_router_exactly(self) -> None:
        api = _hex_lite()
        before = _dump(api)
        apply_guest_isolation(api)
        result = remove_guest_isolation(api)
        assert sorted(result.ports_changed) == ["ether2", "ether3", "ether4", "ether5"]
        assert result.guard_rows_removed == 1
        after = _dump(api)
        assert after[_PORT] == before[_PORT]
        assert after[_FILTER] == before[_FILTER]
        assert not read_guest_isolation(api).enabled

    def test_only_our_horizon_is_cleared(self) -> None:
        api = _hex_lite()
        apply_guest_isolation(api)
        # Someone else puts a port of another bridge in their own group.
        api._menus[_PORT].append(
            {".id": "*X", "bridge": "bridge-office", "interface": "ether9", "horizon": "2"}
        )
        remove_guest_isolation(api)
        assert _ports(api)["ether9"] == "2"

    def test_remove_on_a_clean_router_writes_nothing(self) -> None:
        api = _hex_lite()
        remove_guest_isolation(api)
        assert api.ops == []

    def test_a_remove_the_router_ignores_is_reported(self) -> None:
        api = _hex_lite()
        apply_guest_isolation(api)
        api.silently_ignore_updates.add(_PORT)
        with pytest.raises(FirewallPushFailed) as info:
            remove_guest_isolation(api)
        assert info.value.restored is False


def _with_radios() -> _Api:
    """A hAP-style router: ether2 + a legacy wlan1 + a RouterOS-7 wifi1 in
    the guest bridge."""
    api = _hex_lite({
        _PORT: [
            {".id": "*P2", "bridge": "bridge", "interface": "ether2", "horizon": "none"},
            {".id": "*PW", "bridge": "bridge", "interface": "wlan1", "horizon": "none"},
            {".id": "*PF", "bridge": "bridge", "interface": "wifi1", "horizon": "none"},
        ],
        ("interface",): [
            {"name": "ether1", "type": "ether", "running": "true"},
            {"name": "ether2", "type": "ether", "running": "true"},
            {"name": "wlan1", "type": "wlan", "running": "true"},
            {"name": "wifi1", "type": "wifi", "running": "true"},
            {"name": "bridge", "type": "bridge", "running": "true"},
        ],
        ("interface", "wireless"): [
            {".id": "*W1", "name": "wlan1", "default-forwarding": "true"},
        ],
        ("interface", "wifi"): [
            {".id": "*F1", "name": "wifi1"},
        ],
    })
    return api


class TestRadios:
    def test_radios_are_recorded_then_isolated_and_restored_exactly(self) -> None:
        api = _with_radios()
        before = _dump(api)
        result = apply_guest_isolation(api)
        assert sorted(result.radios_changed) == ["wifi1", "wlan1"]
        wlan = next(iter(api.path("interface", "wireless")))
        wifi = next(iter(api.path("interface", "wifi")))
        assert wlan["default-forwarding"] == "no"
        assert wifi["datapath.client-isolation"] == "yes"
        members = {m["interface"]: m["comment"] for m in api.path("interface", "list", "member")}
        assert members == {
            "wlan1": "cloudguest-iso wireless default-forwarding=yes",
            "wifi1": "cloudguest-iso wifi client-isolation=unset",
        }
        # The record is written before the radio it describes.
        ops = [(op[0], op[1]) for op in api.ops]
        assert ops.index(("add", ("interface", "list", "member"))) < ops.index(
            ("update", ("interface", "wireless"))
        )
        status = read_guest_isolation(api)
        assert status.consistent and all(r.isolated for r in status.radios)

        remove_guest_isolation(api)
        after = _dump(api)
        assert [dict(r) for r in after[("interface", "wireless")]] == [
            {".id": "*W1", "name": "wlan1", "default-forwarding": "yes"}
        ]
        assert after[("interface", "wifi")] == before[("interface", "wifi")]
        assert after[_PORT] == before[_PORT]
        assert list(api.path("interface", "list")) == []
        assert list(api.path("interface", "list", "member")) == []

    def test_a_radio_changed_by_hand_since_is_left_alone(self) -> None:
        api = _with_radios()
        apply_guest_isolation(api)
        api._menus[("interface", "wireless")][0]["default-forwarding"] = "yes"
        result = remove_guest_isolation(api)
        assert "wlan1" in result.left_alone

    def test_a_radio_already_isolated_by_its_profile_is_not_touched(self) -> None:
        api = _with_radios()
        api._menus[("interface", "wifi")][0]["datapath"] = "dp-guest"
        api._menus[("interface", "wifi", "datapath")] = [
            {"name": "dp-guest", "client-isolation": "yes"}
        ]
        result = apply_guest_isolation(api)
        assert "wifi1" not in result.radios_changed

    def test_capsman_managed_radio_is_not_written(self) -> None:
        api = _with_radios()
        api._menus[("interface", "wifi")][0]["configuration.manager"] = "capsman"
        apply_guest_isolation(api)
        assert "datapath.client-isolation" not in next(iter(api.path("interface", "wifi")))
        status = read_guest_isolation(api)
        wifi = next(r for r in status.radios if r.interface == "wifi1")
        assert not wifi.supported and wifi.excluded_reason == "capsman"


class TestAdapter:
    async def test_refusal_and_failure_map_to_the_firewall_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import wyfy_device_gateway.mikrotik_adapter as gateway
        from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor

        api = _hex_lite({("ip", "hotspot"): []})
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        creds = DeviceCredentials(
            vendor=DeviceVendor.MIKROTIK, host="10.0.0.1", username="u", secret="p"
        )
        with pytest.raises(MikroTikFirewallRefusedError) as info:
            await MikroTikAdapter().apply_guest_isolation(creds)
        assert info.value.code == ISOLATION_NO_HOTSPOT

        api = _hex_lite()
        api.silently_ignore_updates.add(_PORT)
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        with pytest.raises(MikroTikFirewallPushFailedError) as failed:
            await MikroTikAdapter().apply_guest_isolation(creds)
        assert failed.value.restored is True

        api = _hex_lite()
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        status = await MikroTikAdapter().read_guest_isolation(creds)
        assert status.refusal is None and not status.enabled
        assert RECORD_LIST  # exported

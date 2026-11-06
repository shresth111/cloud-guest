"""``MikroTikAdapter.read_lan_snapshot``: one connection, read-only, port
link facts + MAC-to-port table + clock offset. Fixture rows are the shapes
read off the HKM hEX lite (RouterOS 7.21.4) on 2026-10-19."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import LanBridgeHost
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikDeviceError,
    _router_clock_offset_seconds,
)

_INTERFACES = [
    {"name": "ether1", "type": "ether", "running": True, "disabled": False,
     "link-downs": 0, "last-link-up-time": "2026-10-17 14:17:54",
     "rx-byte": 1291067947, "tx-byte": 2826940432},
    {"name": "ether3", "type": "ether", "running": False, "disabled": False,
     "link-downs": 5, "last-link-down-time": "2026-10-19 07:09:20",
     "last-link-up-time": "2026-10-18 21:31:23",
     "rx-byte": 2832574449, "tx-byte": 1221918868},
    {"name": "bridge", "type": "bridge", "running": True, "disabled": False,
     "link-downs": 0},
]
_HOSTS = [
    {"mac-address": "38:32:7a:1f:33:89", "on-interface": "bridge",
     "bridge": "bridge", "local": True},
    {"mac-address": "B0:19:21:B9:B5:DC", "on-interface": "ether3",
     "bridge": "bridge", "local": False},
]
_MEMBERS = [{"interface": "ether3", "bridge": "bridge"}]


def _api(clock):
    return FakeRouterOSApi(
        command_replies={
            "/interface/print": _INTERFACES,
            "/interface/bridge/host/print": _HOSTS,
            "/interface/bridge/port/print": _MEMBERS,
            "/system/clock/print": clock,
        }
    )


@pytest.mark.asyncio
async def test_one_connection_four_reads_trimmed(
    patch_connect, mikrotik_creds, monkeypatch
):
    # Router clock 05:30 ahead of UTC (IST).
    now = datetime(2026, 10, 19, 6, 0, 0, tzinfo=UTC).timestamp()
    monkeypatch.setattr("wyfy_device_gateway.mikrotik_adapter.time.time", lambda: now)
    api = _api([{"date": "2026-10-19", "time": "11:30:00"}])
    patch_connect(api)

    snap = await MikroTikAdapter().read_lan_snapshot(mikrotik_creds)

    assert [c[0] for c in api.command_calls] == [
        "/interface/print",
        "/interface/bridge/host/print",
        "/interface/bridge/port/print",
        "/system/clock/print",
    ]
    assert ".proplist" in api.command_calls[0][1]
    assert ".proplist" in api.command_calls[1][1]
    assert not api.add_calls and not api.update_calls and not api.remove_calls
    assert api.closed is True
    assert snap.clock_offset_seconds == 19800
    ether3 = next(p for p in snap.ports if p.name == "ether3")
    assert ether3.running is False
    assert ether3.link_downs == 5
    # 07:09:20 IST -> 01:39:20 UTC
    assert ether3.last_link_down_at == "2026-10-19T01:39:20+00:00"
    assert ether3.rx_bytes == 2832574449
    bridge = next(p for p in snap.ports if p.name == "bridge")
    assert bridge.last_link_down_at is None
    assert snap.hosts[0] == LanBridgeHost(
        mac_address="38:32:7A:1F:33:89", on_interface="bridge",
        bridge="bridge", local=True,
    )
    assert snap.bridge_of_port == {"ether3": "bridge"}


@pytest.mark.asyncio
async def test_unreadable_clock_leaves_times_none(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        command_replies={"/interface/print": _INTERFACES},
        raise_on_command={"/system/clock/print": LibRouterosError("denied")},
    )
    patch_connect(api)

    snap = await MikroTikAdapter().read_lan_snapshot(mikrotik_creds)

    assert snap.clock_offset_seconds is None
    assert all(p.last_link_down_at is None for p in snap.ports)
    assert next(p for p in snap.ports if p.name == "ether3").link_downs == 5


@pytest.mark.asyncio
async def test_interface_read_failure_raises(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        raise_on_command={"/interface/print": LibRouterosError("bad")}
    )
    patch_connect(api)
    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().read_lan_snapshot(mikrotik_creds)
    assert api.closed is True


def test_legacy_clock_format_parses():
    now = datetime(2026, 10, 19, 6, 0, 0, tzinfo=UTC).timestamp()
    rows = [{"date": "oct/19/2026", "time": "06:00:00"}]
    assert _router_clock_offset_seconds(rows, now) == 0
    assert _router_clock_offset_seconds([{"date": "x", "time": "y"}], now) is None

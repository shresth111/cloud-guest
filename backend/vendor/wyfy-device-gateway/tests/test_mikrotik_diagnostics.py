"""Diagnostics: ``ping`` (shared verbatim by network_diagnostics and isp
call sites) and ``traceroute`` -- ported from
``network_diagnostics/device_adapters.py`` /
``isp/device_adapters.py``."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import ArpPingResult, PingResult, TracerouteResult
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError


@pytest.mark.asyncio
async def test_ping_reads_last_cumulative_row(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        command_replies={
            "/tool/ping": [
                {"sent": "1", "received": "1"},
                {
                    "sent": "5",
                    "received": "5",
                    "packet-loss": "0",
                    "avg-rtt": "1ms200us",
                },
            ],
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().ping(
        mikrotik_creds, target="8.8.8.8", count=5, timeout_seconds=10
    )

    assert result == PingResult(
        sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=1.2
    )
    assert api.closed is True


@pytest.mark.asyncio
async def test_ping_empty_rows_is_total_loss(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(command_replies={"/tool/ping": []})
    patch_connect(api)

    result = await MikroTikAdapter().ping(
        mikrotik_creds, target="8.8.8.8", count=4, timeout_seconds=10
    )

    assert result.sent == 4
    assert result.received == 0
    assert result.packet_loss_percentage == 100.0
    assert result.avg_rtt_ms is None


@pytest.mark.asyncio
async def test_ping_operation_failure_raises(patch_connect, mikrotik_creds):
    from librouteros.exceptions import LibRouterosError

    api = FakeRouterOSApi(raise_on_command={"/tool/ping": LibRouterosError("bad cmd")})
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().ping(
            mikrotik_creds, target="8.8.8.8", count=4, timeout_seconds=10
        )
    assert api.closed is True


@pytest.mark.asyncio
async def test_traceroute_collapses_consecutive_same_address_rows(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        command_replies={
            "/tool/traceroute": [
                {"address": "10.0.0.1", "loss": "0", "avg": "1ms"},
                {"address": "10.0.0.1", "loss": "0", "avg": "2ms"},
                {"address": "8.8.8.8", "loss": "0", "avg": "15ms"},
            ],
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().traceroute(
        mikrotik_creds, target="8.8.8.8", max_hops=30, timeout_seconds=10
    )

    assert isinstance(result, TracerouteResult)
    assert [h.hop_number for h in result.hops] == [1, 2]
    assert result.hops[0].address == "10.0.0.1"
    assert result.hops[0].avg_rtt_ms == 2.0
    assert result.hops[1].address == "8.8.8.8"


@pytest.mark.asyncio
async def test_traceroute_timed_out_hop_has_no_address_and_full_loss(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        command_replies={"/tool/traceroute": [{"address": None, "loss": "100"}]}
    )
    patch_connect(api)

    result = await MikroTikAdapter().traceroute(
        mikrotik_creds, target="8.8.8.8", max_hops=30, timeout_seconds=10
    )

    (hop,) = result.hops
    assert hop.address is None
    assert hop.packet_loss_percentage == 100.0


@pytest.mark.asyncio
async def test_traceroute_operation_failure_raises(patch_connect, mikrotik_creds):
    from librouteros.exceptions import LibRouterosError

    api = FakeRouterOSApi(
        raise_on_command={"/tool/traceroute": LibRouterosError("bad cmd")}
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().traceroute(
            mikrotik_creds, target="8.8.8.8", max_hops=30, timeout_seconds=10
        )


# Reply rows captured from a hEX lite (RouterOS 7.23.3), 2026-09-17: ARP ping
# at a TP-Link TL-WR845N that drops ICMP, and at an unused address.
_ARP_PING_ANSWERED = [
    {"seq": 0, "host": "A8:29:48:A9:36:3A", "time": "531us", "sent": 1, "received": 1,
     "packet-loss": 0, "min-rtt": "531us", "avg-rtt": "531us", "max-rtt": "531us"},
    {"seq": 1, "host": "A8:29:48:A9:36:3A", "time": "411us", "sent": 2, "received": 2,
     "packet-loss": 0, "min-rtt": "411us", "avg-rtt": "471us", "max-rtt": "531us"},
]
_ARP_PING_SILENT = [
    {"seq": 0, "host": "192.168.88.200", "status": "timeout", "sent": 1, "received": 0,
     "packet-loss": 100},
    {"seq": 1, "host": "192.168.88.200", "status": "timeout", "sent": 2, "received": 0,
     "packet-loss": 100},
]


@pytest.mark.asyncio
async def test_arp_ping_sends_arp_mode_on_the_given_interface(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(command_replies={"/tool/ping": _ARP_PING_ANSWERED})
    patch_connect(api)

    result = await MikroTikAdapter().arp_ping(
        mikrotik_creds, target="192.168.88.253", interface="bridge", count=2
    )

    assert api.command_calls == [
        (
            "/tool/ping",
            {
                "address": "192.168.88.253",
                "count": "2",
                "arp-ping": "yes",
                "interface": "bridge",
            },
        )
    ]
    assert result == ArpPingResult(
        sent=2, received=2, replied_macs=frozenset({"A8:29:48:A9:36:3A"})
    )
    assert api.closed is True


@pytest.mark.asyncio
async def test_arp_ping_timeout_rows_report_no_mac(patch_connect, mikrotik_creds):
    """A timed-out row's ``host`` is the target IP; it must not be read as a
    replying device."""
    api = FakeRouterOSApi(command_replies={"/tool/ping": _ARP_PING_SILENT})
    patch_connect(api)

    result = await MikroTikAdapter().arp_ping(
        mikrotik_creds, target="192.168.88.200", interface="bridge", count=2
    )

    assert result == ArpPingResult(sent=2, received=0, replied_macs=frozenset())


@pytest.mark.asyncio
async def test_arp_ping_failure_raises(patch_connect, mikrotik_creds):
    from librouteros.exceptions import LibRouterosError

    api = FakeRouterOSApi(raise_on_command={"/tool/ping": LibRouterosError("bad cmd")})
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().arp_ping(
            mikrotik_creds, target="192.168.88.253", interface="bridge", count=2
        )

"""Monitored-device health: debounce, reason codes, port link facts,
history and the per-router LAN snapshot.

The HKM case (2026-10-19) is the reference: the venue AP's port ether3 had
been link-down since 07:09 with ``link-downs=5``, the AP's bridge-host entry
had aged out, and the dashboard said only "Down" -- the owner read that as
our bug. These tests pin that the sweep now says *why*, from one router read
per sweep, and that one dropped probe no longer flips a device to DOWN.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.domains.connected_devices.device_adapters import (
    LanBridgeHost,
    LanPort,
    LanSnapshot,
)
from app.domains.connected_devices.exceptions import ConnectedDeviceOperationError
from app.domains.connected_devices.health import (
    HealthReason,
    HealthState,
    Observation,
    judge,
)
from app.domains.connected_devices.models import MonitoredDeviceEvent
from app.domains.connected_devices.service import (
    run_monitored_hardware_liveness_sweep,
)
from tests.unit.test_monitored_hardware_liveness import (
    _ANSWERS,
    _SILENT,
    FakeLivenessRepository,
    FakeLivenessRouterLookup,
    FakePingAdapter,
    _discovered,
    _make_device,
    _make_monitored,
    _make_router,
)

AP_MAC = "B0:19:21:B9:B5:DC"
AP_IP = "10.5.50.248"


def _port(name: str = "ether3", **kw: object) -> LanPort:
    fields: dict[str, object] = {
        "name": name,
        "type": "ether",
        "running": True,
        "disabled": False,
        "link_downs": 5,
        "last_link_down_at": "2026-10-19T01:39:20+00:00",
        "last_link_up_at": "2026-10-18T16:01:23+00:00",
        "rx_bytes": 1_000_000,
        "tx_bytes": 2_000_000,
    }
    fields.update(kw)
    return LanPort(**fields)


def _bridge() -> LanPort:
    return LanPort(
        name="bridge", type="bridge", running=True, disabled=False,
        link_downs=0, last_link_down_at=None, last_link_up_at=None,
        rx_bytes=None, tx_bytes=None,
    )


def _host(mac: str, port: str = "ether3") -> LanBridgeHost:
    return LanBridgeHost(
        mac_address=mac, on_interface=port, bridge="bridge", local=False
    )


def _snapshot(ports=(), hosts=()) -> LanSnapshot:
    return LanSnapshot(
        ports=(_bridge(), *ports),
        hosts=tuple(hosts),
        bridge_of_port={p.name: "bridge" for p in ports},
        clock_offset_seconds=19800,
    )


def _setup(*, is_active: bool = True, interface: str | None = "bridge"):
    router_lookup = FakeLivenessRouterLookup()
    router = router_lookup.add(_make_router())
    device = _make_device(
        router, mac_address=AP_MAC, ip_address=AP_IP, is_active=is_active,
        connected_at=datetime.now(UTC) - timedelta(days=16),
        last_seen_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    device.interface = interface
    repository = FakeLivenessRepository(
        targets=[(device, _make_monitored(router, mac_address=AP_MAC))]
    )
    return router_lookup, repository, device


async def _sweep(repository, router_lookup, adapter, **kw):
    return await run_monitored_hardware_liveness_sweep(
        repository, router_lookup, device_adapter_resolver=lambda _v: adapter, **kw
    )


# ---------------------------------------------------------------------------
# The state machine, as a table
# ---------------------------------------------------------------------------


def _judge(prev: HealthState, failures: int, **obs: object):
    return judge(
        previous_state=prev,
        previous_failures=failures,
        observation=Observation(**obs),
        down_after=2,
        flap_threshold=3,
    )


class TestJudge:
    def test_answer_is_up_with_the_probe_that_answered(self) -> None:
        v = _judge(HealthState.DOWN, 4, alive=True, method=HealthReason.ARP)
        assert (v.state, v.reason, v.consecutive_failures) == (
            HealthState.UP, HealthReason.ARP, 0,
        )

    def test_first_miss_is_degraded_not_down(self) -> None:
        v = _judge(HealthState.UP, 0, alive=False, arp_attempted=True)
        assert (v.state, v.reason, v.is_active) == (
            HealthState.DEGRADED, HealthReason.PROBE_FAILING, True,
        )

    def test_second_miss_is_down_with_why(self) -> None:
        v = _judge(HealthState.DEGRADED, 1, alive=False, arp_attempted=True)
        assert (v.state, v.reason, v.is_active) == (
            HealthState.DOWN, HealthReason.NO_ARP_REPLY, False,
        )
        v = _judge(HealthState.DEGRADED, 1, alive=False)
        assert v.reason == HealthReason.NO_PING_REPLY
        v = _judge(HealthState.DEGRADED, 1, alive=False, on_lan=False)
        assert v.reason == HealthReason.NOT_ON_LAN

    def test_port_link_down_skips_the_debounce(self) -> None:
        v = _judge(HealthState.UP, 0, alive=False, port_running=False)
        assert (v.state, v.reason) == (HealthState.DOWN, HealthReason.PORT_LINK_DOWN)
        v = _judge(HealthState.UP, 0, alive=False, port_disabled=True)
        assert v.reason == HealthReason.PORT_DISABLED

    def test_flapping_port_is_degraded_while_answering(self) -> None:
        v = _judge(HealthState.UP, 0, alive=True, link_flaps_24h=3)
        assert (v.state, v.reason, v.is_active) == (
            HealthState.DEGRADED, HealthReason.LINK_FLAPPING, True,
        )

    def test_down_device_missing_again_stays_down(self) -> None:
        v = _judge(HealthState.DOWN, 5, alive=False)
        assert v.state == HealthState.DOWN and v.consecutive_failures == 6


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------


class TestDebounce:
    async def test_one_dropped_sweep_no_longer_flips_to_down(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(result=_SILENT)

        first = await _sweep(repository, router_lookup, adapter)

        assert device.is_active is True  # alerts read this: no alert yet
        health = repository.health[device.id]
        assert (health.state, health.reason) == ("degraded", "probe_failing")
        assert first.devices_up == 1 and first.devices_degraded == 1

        second = await _sweep(repository, router_lookup, adapter)

        assert device.is_active is False
        assert repository.health[device.id].state == "down"
        assert second.devices_down == 1
        transitions = [
            (e.from_state, e.to_state) for e in repository.events if e.kind == "state"
        ]
        assert transitions == [(None, "degraded"), ("degraded", "down")]

    async def test_recovery_is_immediate_and_resets_up_since(self) -> None:
        router_lookup, repository, device = _setup(is_active=False)
        adapter = FakePingAdapter(result=_SILENT)
        await _sweep(repository, router_lookup, adapter)
        down_since = repository.health[device.id].since

        adapter.result = _ANSWERS
        await _sweep(repository, router_lookup, adapter)

        health = repository.health[device.id]
        assert health.state == "up" and health.reason == "icmp"
        assert health.since >= down_since
        assert health.last_rtt_ms == 1.0
        assert device.is_active is True

    async def test_degraded_blip_keeps_up_since(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(result=_ANSWERS)
        await _sweep(repository, router_lookup, adapter)
        up_since = repository.health[device.id].since

        adapter.result = _SILENT
        await _sweep(repository, router_lookup, adapter)
        adapter.result = _ANSWERS
        await _sweep(repository, router_lookup, adapter)

        assert repository.health[device.id].since == up_since


class TestPortFacts:
    async def test_hkm_port_link_down_is_down_now_and_says_which_port(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(
            result=_ANSWERS,
            snapshot=_snapshot(ports=[_port()], hosts=[_host(AP_MAC)]),
        )
        await _sweep(repository, router_lookup, adapter)
        assert repository.health[device.id].port_name == "ether3"

        # The cable comes out: link down, bridge-host entry gone.
        adapter.result = _SILENT
        adapter.snapshot = _snapshot(ports=[_port(running=False, link_downs=6)])
        await _sweep(repository, router_lookup, adapter)

        health = repository.health[device.id]
        assert (health.state, health.reason) == ("down", "port_link_down")
        assert health.port_name == "ether3"  # remembered
        assert health.port_running is False
        assert health.port_last_link_down_at == datetime(
            2026, 10, 19, 1, 39, 20, tzinfo=UTC
        )
        assert device.is_active is False
        # A dead link answers nothing: no lease read, no ARP ping.
        assert adapter.discover_calls == 0
        assert adapter.arp_ping_calls == []

    async def test_one_snapshot_per_router_not_per_device(self) -> None:
        router_lookup, repository, device = _setup()
        router = await router_lookup.get_router(device.router_id)
        other = _make_device(router, mac_address="AA:AA:AA:AA:AA:01")
        repository.targets.append(
            (other, _make_monitored(router, mac_address=other.mac_address))
        )
        adapter = FakePingAdapter(result=_ANSWERS)

        await _sweep(repository, router_lookup, adapter)

        assert adapter.snapshot_calls == 1

    async def test_link_flaps_are_counted_and_degrade(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(
            result=_ANSWERS,
            snapshot=_snapshot(ports=[_port(link_downs=5)], hosts=[_host(AP_MAC)]),
        )
        await _sweep(repository, router_lookup, adapter)
        adapter.snapshot = _snapshot(
            ports=[_port(link_downs=8)], hosts=[_host(AP_MAC)]
        )
        await _sweep(repository, router_lookup, adapter)

        flaps = [e for e in repository.events if e.kind == "link_down"]
        assert [(e.count, e.detail) for e in flaps] == [(3, "ether3")]
        health = repository.health[device.id]
        # It rebooted three times without missing a ping: still visible.
        assert (health.state, health.reason) == ("degraded", "link_flapping")
        assert device.is_active is True

    async def test_router_reboot_resetting_the_counter_is_not_a_flap(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(
            result=_ANSWERS,
            snapshot=_snapshot(ports=[_port(link_downs=5)], hosts=[_host(AP_MAC)]),
        )
        await _sweep(repository, router_lookup, adapter)
        adapter.snapshot = _snapshot(
            ports=[_port(link_downs=0, rx_bytes=10)], hosts=[_host(AP_MAC)]
        )
        await _sweep(repository, router_lookup, adapter)

        assert not [e for e in repository.events if e.kind == "link_down"]
        assert repository.health[device.id].rx_bps is None  # gap, not spike

    async def test_traffic_and_clients_behind(self) -> None:
        router_lookup, repository, device = _setup()
        guests = [_host(f"02:00:00:00:00:0{i}") for i in range(4)]
        elsewhere = _host("02:00:00:00:01:00", port="ether4")
        adapter = FakePingAdapter(
            result=_ANSWERS,
            snapshot=_snapshot(
                ports=[_port(), _port("ether4")],
                hosts=[_host(AP_MAC), *guests, elsewhere],
            ),
        )
        await _sweep(repository, router_lookup, adapter)
        health = repository.health[device.id]
        assert health.clients_behind == 4
        assert health.rx_bps is None  # no previous reading yet

        health.port_counters_at -= timedelta(seconds=30)
        adapter.snapshot = _snapshot(
            ports=[_port(rx_bytes=1_000_000 + 375_000), _port("ether4")],
            hosts=[_host(AP_MAC), *guests],
        )
        await _sweep(repository, router_lookup, adapter)

        # 375 kB over ~30 s (the sweep's clock runs a few ms past 30 s).
        assert 99_000 <= repository.health[device.id].rx_bps <= 100_000

    async def test_device_that_moved_ports_is_up_and_forgets_the_old_port(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(
            result=_ANSWERS,
            snapshot=_snapshot(ports=[_port()], hosts=[_host(AP_MAC)]),
        )
        await _sweep(repository, router_lookup, adapter)
        adapter.snapshot = _snapshot(ports=[_port(running=False)])

        await _sweep(repository, router_lookup, adapter)

        health = repository.health[device.id]
        assert health.state == "up"
        assert health.port_name is None

    async def test_snapshot_read_failure_falls_back_to_plain_probing(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(result=_ANSWERS)

        async def broken(_creds):
            raise ConnectedDeviceOperationError("read_lan_snapshot", "no such menu")

        adapter.read_lan_snapshot = broken
        summary = await _sweep(repository, router_lookup, adapter)

        assert summary.routers_probed == 1 and summary.devices_up == 1
        assert repository.health[device.id].port_name is None


class TestArpInterface:
    async def test_null_interface_uses_the_macs_bridge(self) -> None:
        """Before: ``interface`` NULL (lease-only sighting) meant no ARP ping
        at all, so an ICMP-dropping AP read DOWN forever."""
        router_lookup, repository, device = _setup(interface=None)
        adapter = FakePingAdapter(
            result=_SILENT,
            discovered=[_discovered(AP_MAC, AP_IP)],
            arp_replies={AP_IP: frozenset({AP_MAC})},
            snapshot=_snapshot(ports=[_port()], hosts=[_host(AP_MAC)]),
        )

        await _sweep(repository, router_lookup, adapter)

        assert adapter.arp_ping_calls == [{"target": AP_IP, "interface": "bridge"}]
        assert repository.health[device.id].reason == "arp"

    async def test_bridge_port_interface_is_mapped_to_its_bridge(self) -> None:
        router_lookup, repository, device = _setup(interface="ether3")
        adapter = FakePingAdapter(
            result=_SILENT,
            discovered=[_discovered(AP_MAC, AP_IP)],
            snapshot=_snapshot(ports=[_port()], hosts=[_host(AP_MAC)]),
        )

        await _sweep(repository, router_lookup, adapter)

        assert adapter.arp_ping_calls[0]["interface"] == "bridge"


class TestHistory:
    async def test_ip_change_is_an_event(self) -> None:
        router_lookup, repository, device = _setup()
        adapter = FakePingAdapter(
            results_by_target={AP_IP: _SILENT, "10.5.50.9": _ANSWERS},
            discovered=[_discovered(AP_MAC, "10.5.50.9")],
        )

        await _sweep(repository, router_lookup, adapter)

        changes = [e.detail for e in repository.events if e.kind == "ip_changed"]
        assert changes == [f"{AP_IP} -> 10.5.50.9"]

    async def test_old_events_are_pruned(self) -> None:
        router_lookup, repository, device = _setup()
        repository.events.append(
            MonitoredDeviceEvent(
                id=uuid.uuid4(), connected_device_id=device.id,
                organization_id=device.organization_id,
                location_id=device.location_id, kind="state",
                occurred_at=datetime.now(UTC) - timedelta(days=31),
            )
        )
        await _sweep(repository, router_lookup, FakePingAdapter(result=_ANSWERS))

        assert all(
            e.occurred_at > datetime.now(UTC) - timedelta(days=30)
            for e in repository.events
        )

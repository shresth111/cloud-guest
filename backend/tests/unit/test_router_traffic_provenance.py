"""Per-port traffic and where a health reading says it came from.

Two defects sat next to each other in the router-health pipeline, and
both were invisible for the same reason: the dashboard rendered a
plausible page either way.

1. THE ROUTEROS-API SWEEP NEVER RECORDED ITS OWN PROVENANCE.
   ``record_health_snapshot`` grew a ``metrics_source`` parameter when the
   SNMP sweep landed. The pre-existing RouterOS-API sweep was never
   updated to pass it, so it kept defaulting to ``None`` -- and ``None``
   already meant something specific and different: "this row predates the
   column". Every API-sourced reading since therefore claimed its
   transport was unknown, and the UI dutifully labelled it "Not
   recorded". Nothing raised. Two docstrings asserted the opposite of
   what the code did.

2. THE API SWEEP THREW AWAY COUNTERS IT HAD ALREADY FETCHED.
   Per-interface traffic could only ever be populated by the SNMP sweep,
   which is gated behind ``Router.snmp_enabled`` (default ``False``, and
   no code path anywhere sets it) -- so the panel was empty fleet-wide.
   Meanwhile ``_get_interface_traffic_counters_sync`` was reading the
   *entire* ``/interface`` table over the already-open API session and
   keeping one row. The data was in hand and discarded.

What these tests pin, in the order they matter:

  * the row shape both transports produce is identical, enforced through
    one shared builder rather than by two lists of string keys that agree
    today;
  * ``.id`` is parsed as hexadecimal, because ``"*A"`` is interface ten
    and a decimal read raises on it;
  * "not measured" stays distinguishable from "measured, and empty" at
    every layer -- ``None``, never ``[]``, never ``0``;
  * a failed interface read degrades a reading, never loses it.
"""

from __future__ import annotations

from dataclasses import dataclass

from librouteros.exceptions import LibRouterosError
from wyfy_device_gateway.contract import (
    DeviceCredentials,
    DeviceInterfaceCounters,
    DeviceVendor,
)
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    _interface_counters_from_rows,
    _routeros_row_index,
)
from wyfy_device_gateway.snmp_poller import SnmpInterfaceCounters

from app.domains.provisioning_engine.device_adapters import DeviceHealthResult
from app.domains.provisioning_engine.service import (
    _interface_counter_rows,
    run_router_health_poll_sweep,
)
from app.domains.router_provisioning.constants import MetricsSource
from tests.unit.test_provisioning_engine import (
    FakeProvisioningEngineRepository,
    FakeRouterLookup,
    FakeRouterProvisioningLookup,
    _HealthPollAdapter,
    _make_router,
)


class TestRouterOsRowIndex:
    """``.id`` is hex. This is the whole reason it is a named function."""

    def test_parses_hexadecimal_not_decimal(self) -> None:
        # The interesting case: a router with more than nine interfaces.
        # `int("A")` raises; `int("A", 16)` is 10. A hEX lite has five
        # ethernet ports plus bridge, wlan and tunnel interfaces, so this
        # is reached on ordinary hardware, not a hypothetical.
        assert _routeros_row_index("*A") == 10
        assert _routeros_row_index("*ff") == 255
        assert _routeros_row_index("*1") == 1

    def test_returns_none_rather_than_a_number_for_unparseable_input(self) -> None:
        # None -- never 0. A row given index 0 joins whatever other row
        # was also given index 0, silently merging two interfaces' series.
        for raw in ("1", "", "*", "*zz", None, 7):
            assert _routeros_row_index(raw) is None, raw


class TestInterfaceCountersFromRows:
    def test_maps_a_real_routeros_interface_row(self) -> None:
        (counter,) = _interface_counters_from_rows(
            [
                {
                    ".id": "*2",
                    "name": "ether1",
                    "running": True,
                    "rx-byte": "123456",
                    "tx-byte": "654321",
                }
            ]
        )
        assert counter == DeviceInterfaceCounters(
            if_index=2,
            if_name="ether1",
            if_oper_status_up=True,
            in_octets=123456,
            out_octets=654321,
        )

    def test_absent_counters_are_none_not_zero(self) -> None:
        """Zero is a measurement. Absent is not.

        Defaulting a missing ``rx-byte`` to 0 does two things, both bad:
        it draws an idle interface that may be saturated, and it makes
        the *next* poll's delta the interface's entire lifetime total,
        which renders as one enormous spike.
        """
        (counter,) = _interface_counters_from_rows(
            [{".id": "*1", "name": "ether1", "running": False}]
        )
        assert counter.in_octets is None
        assert counter.out_octets is None
        assert counter.if_oper_status_up is False

    def test_drops_loopback_and_unusable_rows(self) -> None:
        counters = _interface_counters_from_rows(
            [
                {".id": "*1", "name": "lo", "rx-byte": "1"},
                {".id": "*2", "name": "", "rx-byte": "1"},
                {"name": "ether9", "rx-byte": "1"},  # no .id
                {".id": "*3", "name": "ether1", "rx-byte": "1"},
            ]
        )
        assert [c.if_name for c in counters] == ["ether1"]

    def test_empty_read_is_none_not_an_empty_tuple(self) -> None:
        # "We took no reading", not "we looked and this router has no
        # interfaces" -- which is never true of a device that answered.
        assert _interface_counters_from_rows([]) is None


class TestSharedRowBuilder:
    """One builder, so the two transports cannot drift apart in shape."""

    def test_snmp_and_routeros_api_produce_identical_rows(self) -> None:
        snmp = SnmpInterfaceCounters(
            if_index=1,
            if_name="ether1",
            if_oper_status_up=True,
            in_octets=10,
            out_octets=20,
        )
        api = DeviceInterfaceCounters(
            if_index=1,
            if_name="ether1",
            if_oper_status_up=True,
            in_octets=10,
            out_octets=20,
        )
        # Not "both contain if_name" -- byte-identical. These land in one
        # JSON column and are read back by one chart, which keys on the
        # exact strings below.
        assert _interface_counter_rows([snmp]) == _interface_counter_rows([api])
        assert _interface_counter_rows([api]) == [
            {
                "if_index": 1,
                "if_name": "ether1",
                "up": True,
                "in_octets": 10,
                "out_octets": 20,
            }
        ]

    def test_none_and_empty_both_yield_none(self) -> None:
        assert _interface_counter_rows(None) is None
        assert _interface_counter_rows([]) is None


class TestMetricsSourceVocabulary:
    def test_values_are_the_strings_the_dashboard_maps(self) -> None:
        """A wire contract, pinned.

        ``toMetricsSource`` in the dashboard matches these two literals
        and falls through to ``null`` for anything else -- and ``null``
        renders as "Not recorded". Renaming a member here would not raise
        anywhere; it would quietly relabel every row written afterwards.
        """
        assert MetricsSource.ROUTEROS_API.value == "routeros_api"
        assert MetricsSource.SNMP.value == "snmp"


@dataclass
class _FakeApi:
    """Stands in for a librouteros connection.

    ``interface_error`` is the case that matters: a router that answers
    ``/system/resource/print`` but refuses the interface listing must
    still yield a usable health reading.
    """

    interface_rows: list[dict[str, object]]
    interface_error: Exception | None = None
    closed: bool = False

    def __call__(self, command: str):
        assert command == "/system/resource/print"
        return iter([{"cpu-load": "20", "free-memory": "1000", "uptime": "1h2m3s"}])

    def path(self, *segments: str):
        assert segments == ("interface",)
        if self.interface_error is not None:
            raise self.interface_error
        return iter(self.interface_rows)

    def close(self) -> None:
        self.closed = True


class TestHealthCheckCarriesInterfaces:
    """The adapter's own read, exercised through the real method."""

    async def _health_check(self, api: _FakeApi):
        adapter = MikroTikAdapter()
        adapter._connect_api = lambda creds: api  # type: ignore[method-assign]
        return await adapter.health_check(
            DeviceCredentials(
                vendor=DeviceVendor.MIKROTIK,
                host="10.20.0.14",
                username="u",
                secret="p",
            )
        )

    async def test_counters_reach_the_result(self) -> None:
        api = _FakeApi(
            interface_rows=[
                {
                    ".id": "*1",
                    "name": "ether1",
                    "running": True,
                    "rx-byte": "500",
                    "tx-byte": "600",
                }
            ]
        )
        result = await self._health_check(api)

        assert result.healthy is True
        assert result.cpu_load_percent == 20
        assert result.interfaces is not None
        assert result.interfaces[0].if_name == "ether1"
        assert result.interfaces[0].in_octets == 500
        assert api.closed is True

    async def test_a_failed_interface_read_degrades_the_reading_not_loses_it(
        self,
    ) -> None:
        """Liveness must survive a failure in the richer half.

        CPU and uptime are what "is this router alive" is decided on.
        Letting an interface-listing failure propagate would turn a poll
        that successfully proved the device is up into an error, and the
        router would be reported unreachable when it plainly answered.
        """
        api = _FakeApi(
            interface_rows=[],
            interface_error=LibRouterosError("no such command prefix"),
        )
        result = await self._health_check(api)

        assert result.healthy is True
        assert result.uptime_seconds == 3723
        assert result.interfaces is None
        assert api.closed is True


class TestApiSweepStampsProvenance:
    """The end-to-end assertion: what the sweep actually persists."""

    async def test_sweep_records_source_and_counters(self) -> None:
        repository = FakeProvisioningEngineRepository()
        router_lookup = FakeRouterLookup()
        router_provisioning = FakeRouterProvisioningLookup()

        router = router_lookup.add(_make_router(), secret="secret-1")
        router.management_ip_address = "10.0.0.1"
        repository.routers_for_health_poll = [router]

        adapter = _HealthPollAdapter(
            healthy_hosts={
                "10.0.0.1": DeviceHealthResult(
                    healthy=True,
                    cpu_load_percent=12.5,
                    free_memory_bytes=1000,
                    uptime_seconds=3600,
                    interfaces=(
                        DeviceInterfaceCounters(
                            if_index=1,
                            if_name="ether1",
                            if_oper_status_up=True,
                            in_octets=10,
                            out_octets=20,
                        ),
                    ),
                )
            }
        )

        await run_router_health_poll_sweep(
            repository,
            router_lookup,
            router_provisioning,
            device_adapter_resolver=lambda vendor: adapter,
        )

        (recorded,) = router_provisioning.health_snapshots_recorded
        assert recorded["metrics_source"] == "routeros_api"
        assert recorded["interface_traffic_counters"] == [
            {
                "if_index": 1,
                "if_name": "ether1",
                "up": True,
                "in_octets": 10,
                "out_octets": 20,
            }
        ]

    async def test_a_reading_without_counters_stores_none_but_still_stamps_source(
        self,
    ) -> None:
        """The two fields are independent.

        An adapter that could not read interfaces still knows perfectly
        well which transport it used. Collapsing both to ``None`` would
        re-create the original defect on exactly the polls most worth
        being able to trace.
        """
        repository = FakeProvisioningEngineRepository()
        router_lookup = FakeRouterLookup()
        router_provisioning = FakeRouterProvisioningLookup()
        router = router_lookup.add(_make_router(), secret="s")
        router.management_ip_address = "10.0.0.1"
        repository.routers_for_health_poll = [router]

        adapter = _HealthPollAdapter(
            healthy_hosts={
                "10.0.0.1": DeviceHealthResult(
                    healthy=True,
                    cpu_load_percent=1.0,
                    free_memory_bytes=1,
                    uptime_seconds=1,
                    interfaces=None,
                )
            }
        )

        await run_router_health_poll_sweep(
            repository,
            router_lookup,
            router_provisioning,
            device_adapter_resolver=lambda vendor: adapter,
        )

        (recorded,) = router_provisioning.health_snapshots_recorded
        assert recorded["interface_traffic_counters"] is None
        assert recorded["metrics_source"] == "routeros_api"


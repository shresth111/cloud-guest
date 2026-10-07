"""``/ip traffic-flow`` export, against the write-capable fake RouterOS API.

What these pin, and why each matters on a real router:

* **One target, ever.** ``target add`` has no unique key; a second push
  must update our marked row, never add another (two targets = every flow
  counted twice). Duplicates already on the device are removed.
* **Idempotent.** An unchanged re-apply issues zero writes.
* **Read-back decides success.** A ``set`` that returns cleanly and
  changes nothing reports ``matches=False`` with the field named.
* **v6 refused before any write.**
* **Foreign targets untouched.** A venue's own NetFlow export stays.
* **Disable removes only our target and switches export off first.**

Nothing here has run against hardware; DESIGN.md §9 H1/H7 is the device check.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError
from wyfy_device_gateway.mikrotik_traffic_flow import (
    TRAFFIC_FLOW_V7_REQUIRED,
    TrafficFlowConfig,
    TrafficFlowRefusal,
    apply_traffic_flow,
    normalize_value,
    plan_traffic_flow,
    read_traffic_flow,
)

MARKER = "wyfy-traffic-flow"
SETTINGS = ("ip", "traffic-flow")
IPFIX = ("ip", "traffic-flow", "ipfix")
TARGET = ("ip", "traffic-flow", "target")

ON = TrafficFlowConfig(
    settings={
        "enabled": "yes",
        "interfaces": "all",
        "cache-entries": "4k",
        "active-flow-timeout": "1m",
        "inactive-flow-timeout": "15s",
        "packet-sampling": "no",
    },
    ipfix={"nat-src-address": "yes", "nat-src-port": "yes"},
    target={
        "dst-address": "10.20.0.1",
        "port": "2055",
        "version": "ipfix",
        "src-address": "10.20.0.31",
    },
    marker=MARKER,
)
OFF = TrafficFlowConfig(
    settings={"enabled": "no"}, ipfix={}, target=None, marker=MARKER
)


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


def _device(
    version: str = "7.16.2 (stable)", targets: list[dict] | None = None
) -> _Api:
    return _Api(
        menus={
            ("system", "resource"): [{"version": version}],
            SETTINGS: [
                {
                    "enabled": False,
                    "interfaces": "all",
                    "cache-entries": "4k",
                    "active-flow-timeout": "30m",
                    "inactive-flow-timeout": "15s",
                    "packet-sampling": False,
                }
            ],
            IPFIX: [{"nat-src-address": False, "nat-src-port": False, "bytes": True}],
            TARGET: list(targets or []),
        }
    )


class TestNormalize:
    @pytest.mark.parametrize(
        ("raw", "want"),
        [
            ("1m", "60s"),
            ("00:01:00", "60s"),
            ("60s", "60s"),
            ("30m", "1800s"),
            ("1h30m", "5400s"),
        ],
    )
    def test_durations_compare_in_seconds(self, raw: str, want: str) -> None:
        assert normalize_value("active-flow-timeout", raw) == want

    def test_booleans_read_as_bool_compare_equal_to_yes_no(self) -> None:
        assert (
            normalize_value("enabled", True)
            == normalize_value("enabled", "yes")
            == "yes"
        )
        assert (
            normalize_value("enabled", False)
            == normalize_value("enabled", "no")
            == "no"
        )

    def test_version_case_is_ignored(self) -> None:
        assert normalize_value("version", "IPFIX") == normalize_value(
            "version", "ipfix"
        )


class TestApply:
    def test_turn_on_adds_target_before_enabling_and_reads_back(self) -> None:
        api = _device()
        result = apply_traffic_flow(api, ON)
        assert result.matches, result.mismatches
        adds = [op for op in api.ops if op[0] == "add"]
        assert len(adds) == 1 and adds[0][1] == TARGET
        assert adds[0][2]["comment"] == MARKER
        # target is in place before export is switched on
        order = [(op[0], op[1]) for op in api.ops]
        assert order.index(("add", TARGET)) < order.index(("update", SETTINGS))

    def test_reapply_is_zero_writes_and_still_one_target(self) -> None:
        api = _device()
        apply_traffic_flow(api, ON)
        api.ops.clear()
        result = apply_traffic_flow(api, ON)
        assert result.writes == ()
        assert api.ops == []
        assert len(result.after.targets) == 1

    def test_existing_marked_target_is_updated_in_place_not_duplicated(self) -> None:
        api = _device(
            targets=[
                {
                    ".id": "*7",
                    "dst-address": "10.20.0.9",
                    "port": 2055,
                    "version": "IPFIX",
                    "src-address": "10.20.0.31",
                    "comment": MARKER,
                }
            ]
        )
        result = apply_traffic_flow(api, ON)
        assert result.matches
        assert not [op for op in api.ops if op[0] == "add"]
        assert ("update", TARGET, {".id": "*7", "dst-address": "10.20.0.1"}) in api.ops

    def test_duplicate_marked_targets_are_collapsed_to_one(self) -> None:
        dup = {
            "dst-address": "10.20.0.1",
            "port": 2055,
            "version": "IPFIX",
            "src-address": "10.20.0.31",
            "comment": MARKER,
        }
        api = _device(targets=[{".id": "*1", **dup}, {".id": "*2", **dup}])
        result = apply_traffic_flow(api, ON)
        assert result.matches
        assert ("remove", TARGET, ("*2",)) in api.ops
        assert len(result.after.targets) == 1

    def test_foreign_target_is_left_alone_and_counted(self) -> None:
        foreign = {
            ".id": "*F",
            "dst-address": "192.0.2.10",
            "port": 9995,
            "version": "9",
            "comment": "venue's own collector",
        }
        api = _device(targets=[foreign])
        result = apply_traffic_flow(api, ON)
        assert result.matches
        assert result.after.foreign_targets == 1
        assert not [op for op in api.ops if op[0] == "remove"]

    def test_silently_ignored_set_is_reported_by_read_back(self) -> None:
        api = _device()
        api.silently_ignore_updates.add(SETTINGS)
        result = apply_traffic_flow(api, ON)
        assert not result.matches
        assert any("enabled" in m for m in result.mismatches)
        assert any("active-flow-timeout" in m for m in result.mismatches)

    def test_routeros_v6_is_refused_before_any_write(self) -> None:
        api = _device(version="6.49.10 (long-term)")
        with pytest.raises(TrafficFlowRefusal) as exc:
            apply_traffic_flow(api, ON)
        assert exc.value.code == TRAFFIC_FLOW_V7_REQUIRED
        assert api.ops == []

    def test_disable_switches_off_first_then_removes_only_our_target(self) -> None:
        foreign = {
            ".id": "*F",
            "dst-address": "192.0.2.10",
            "port": 9995,
            "comment": "x",
        }
        api = _device()
        apply_traffic_flow(api, ON)
        api.path(*TARGET).add(**{k: v for k, v in foreign.items() if k != ".id"})
        api.ops.clear()
        result = apply_traffic_flow(api, OFF)
        assert result.matches, result.mismatches
        kinds = [(op[0], op[1]) for op in api.ops]
        assert kinds[0] == ("update", SETTINGS)
        assert [
            op for op in api.ops if op[0] == "remove"
        ] and result.after.targets == ()
        assert result.after.foreign_targets == 1


class TestPlanIsPure:
    def test_plan_does_not_touch_the_device(self) -> None:
        api = _device()
        state = read_traffic_flow(api, marker=MARKER)
        plan = plan_traffic_flow(state, ON)
        assert api.ops == []
        assert [p[0] for p in plan] == ["set", "add", "set"]


class TestAdapter:
    async def test_adapter_read_and_apply_round_trip(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _device()
        patch_connect(api)
        adapter = MikroTikAdapter()
        before = await adapter.read_traffic_flow(mikrotik_creds, marker=MARKER)
        assert before.settings["enabled"] == "no"
        patch_connect(api)
        result = await adapter.apply_traffic_flow(mikrotik_creds, ON)
        assert result.matches
        assert api.closed

    async def test_device_error_is_wrapped(self, patch_connect, mikrotik_creds) -> None:
        api = _Api(missing_menus={("system", "resource")})
        patch_connect(api)
        with pytest.raises(MikroTikDeviceError):
            await MikroTikAdapter().read_traffic_flow(mikrotik_creds, marker=MARKER)

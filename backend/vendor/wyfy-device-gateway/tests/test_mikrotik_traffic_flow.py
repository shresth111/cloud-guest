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
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError
from wyfy_device_gateway.mikrotik_traffic_flow import (
    TRAFFIC_FLOW_V7_REQUIRED,
    TrafficFlowConfig,
    TrafficFlowRefusal,
    apply_traffic_flow,
    is_our_target,
    normalize_value,
    plan_traffic_flow,
    read_traffic_flow,
)

IDENTITY = {"dst-address": "10.20.0.1", "port": "2055"}
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
    identity=IDENTITY,
)
OFF = TrafficFlowConfig(
    settings={"enabled": "no"}, ipfix={}, target=None, identity=IDENTITY
)
OURS = {
    "dst-address": "10.20.0.1",
    "port": 2055,
    "version": "IPFIX",
    "src-address": "10.20.0.31",
}
FOREIGN = {
    ".id": "*F",
    "dst-address": "192.0.2.10",
    "port": 9995,
    "version": "9",
}


class _TargetMenu:
    """``/ip traffic-flow target`` as RouterOS 7.21.4 behaves: it has no
    ``comment`` property. Measured on a hEX lite -- the first real apply
    failed with "unknown parameter comment" on the ``add``. Everything else
    is the ordinary fake."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __iter__(self):  # noqa: ANN204
        return iter(self._inner)

    def _refuse_comment(self, fields: dict[str, Any]) -> None:
        if "comment" in fields:
            raise LibRouterosError("unknown parameter comment")

    def add(self, **fields: Any) -> str:
        self._refuse_comment(fields)
        return self._inner.add(**fields)

    def update(self, **fields: Any) -> None:
        self._refuse_comment(fields)
        self._inner.update(**fields)

    def remove(self, *ids: Any) -> None:
        self._inner.remove(*ids)


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def path(self, *segments: str) -> Any:
        inner = super().path(*segments)
        return _TargetMenu(inner) if segments == TARGET else inner

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


def _writes(api: _Api) -> list[tuple[str, tuple[str, ...], Any]]:
    return [op for op in api.ops if op[0] in {"add", "update", "remove"}]


def _targets(api: _Api) -> list[dict[str, Any]]:
    return [dict(row) for row in api.path(*TARGET)]


class TestApply:
    def test_turn_on_adds_target_before_enabling_and_reads_back(self) -> None:
        api = _device()
        result = apply_traffic_flow(api, ON)
        assert result.matches, result.mismatches
        adds = [op for op in api.ops if op[0] == "add"]
        assert len(adds) == 1 and adds[0][1] == TARGET
        assert adds[0][2] == dict(ON.target)
        # target is in place before export is switched on
        order = [(op[0], op[1]) for op in api.ops]
        assert order.index(("add", TARGET)) < order.index(("update", SETTINGS))

    def test_no_write_ever_carries_a_comment(self) -> None:
        """Across add, update, de-duplicate and remove. The fake target menu
        refuses ``comment`` the way the device does, so sending one fails
        here too, not only on hardware."""
        api = _device(
            targets=[
                {".id": "*1", **OURS, "version": "9"},
                {".id": "*2", **OURS},
                dict(FOREIGN),
            ]
        )
        apply_traffic_flow(api, ON)
        apply_traffic_flow(api, OFF)
        apply_traffic_flow(_device(), ON)
        for op in _writes(api):
            assert "comment" not in str(op[2]), op
        plan = plan_traffic_flow(read_traffic_flow(_device(), identity=IDENTITY), ON)
        assert all("comment" not in fields for _op, _path, fields in plan)

    def test_a_comment_would_be_refused_by_this_fake(self) -> None:
        with pytest.raises(LibRouterosError, match="unknown parameter comment"):
            _device().path(*TARGET).add(**OURS, comment="x")

    def test_reapply_is_zero_writes_and_still_one_target(self) -> None:
        api = _device()
        apply_traffic_flow(api, ON)
        api.ops.clear()
        result = apply_traffic_flow(api, ON)
        assert result.writes == ()
        assert api.ops == []
        assert len(result.after.targets) == 1

    def test_our_target_is_found_by_address_and_port_and_updated_in_place(
        self,
    ) -> None:
        api = _device(
            targets=[
                {".id": "*7", **OURS, "version": "9", "src-address": "10.20.0.99"},
                dict(FOREIGN),
            ]
        )
        result = apply_traffic_flow(api, ON)
        assert result.matches, result.mismatches
        assert not [op for op in api.ops if op[0] == "add"]
        assert (
            "update",
            TARGET,
            {".id": "*7", "version": "ipfix", "src-address": "10.20.0.31"},
        ) in api.ops
        assert [t[".id"] for t in _targets(api)] == ["*7", "*F"]

    def test_duplicates_of_our_target_are_collapsed_to_one(self) -> None:
        api = _device(
            targets=[{".id": "*1", **OURS}, {".id": "*2", **OURS}, dict(FOREIGN)]
        )
        result = apply_traffic_flow(api, ON)
        assert result.matches
        assert ("remove", TARGET, ("*2",)) in api.ops
        assert len(result.after.targets) == 1
        assert [t[".id"] for t in _targets(api)] == ["*1", "*F"]

    def test_foreign_target_is_left_alone_and_counted(self) -> None:
        api = _device(targets=[dict(FOREIGN)])
        result = apply_traffic_flow(api, ON)
        assert result.matches
        assert result.after.foreign_targets == 1
        assert not [op for op in api.ops if op[0] in {"remove", "update"} and op[1] == TARGET]
        assert dict(FOREIGN) in _targets(api)

    @pytest.mark.parametrize(
        "near_miss",
        [
            {"dst-address": "10.20.0.1", "port": 9995},  # our address, other port
            {"dst-address": "10.20.0.2", "port": 2055},  # our port, other address
        ],
    )
    def test_a_target_sharing_only_half_the_identity_is_foreign(
        self, near_miss: dict[str, Any]
    ) -> None:
        row = {".id": "*H", "version": "9", **near_miss}
        api = _device(targets=[dict(row)])
        result = apply_traffic_flow(api, ON)
        assert result.after.foreign_targets == 1 and len(result.after.targets) == 1
        apply_traffic_flow(api, OFF)
        assert _targets(api) == [row]

    def test_address_printed_with_a_host_mask_is_still_ours(self) -> None:
        """How a target row prints is unmeasured. If ``dst-address`` comes
        back as ``10.20.0.1/32`` it is the same host: no second target, and
        the read-back still matches."""
        api = _device(
            targets=[
                {
                    ".id": "*1",
                    **OURS,
                    "dst-address": "10.20.0.1/32",
                    "src-address": "10.20.0.31/32",
                }
            ]
        )
        result = apply_traffic_flow(api, ON)
        assert result.matches, result.mismatches
        assert not [op for op in api.ops if op[1] == TARGET]
        assert normalize_value("dst-address", "10.20.0.1/32") == "10.20.0.1"
        assert normalize_value("dst-address", "10.20.0.0/24") == "10.20.0.0/24"

    def test_silently_ignored_set_is_reported_by_read_back(self) -> None:
        api = _device()
        api.silently_ignore_updates.add(SETTINGS)
        result = apply_traffic_flow(api, ON)
        assert not result.matches
        assert any("enabled" in m for m in result.mismatches)
        assert any("active-flow-timeout" in m for m in result.mismatches)

    def test_read_back_reports_a_target_the_device_did_not_hold(self) -> None:
        api = _device(targets=[{".id": "*1", **OURS, "version": "9"}])
        api.silently_ignore_updates.add(TARGET)
        result = apply_traffic_flow(api, ON)
        assert not result.matches
        assert any("target version" in m for m in result.mismatches)

    def test_routeros_v6_is_refused_before_any_write(self) -> None:
        api = _device(version="6.49.10 (long-term)")
        with pytest.raises(TrafficFlowRefusal) as exc:
            apply_traffic_flow(api, ON)
        assert exc.value.code == TRAFFIC_FLOW_V7_REQUIRED
        assert api.ops == []

    def test_remove_takes_only_our_target_then_switches_off(self) -> None:
        api = _device()
        apply_traffic_flow(api, ON)
        api.ops.clear()
        result = apply_traffic_flow(api, OFF)
        assert result.matches, result.mismatches
        kinds = [(op[0], op[1]) for op in api.ops]
        assert kinds == [("remove", TARGET), ("update", SETTINGS)]
        assert result.after.targets == () and _targets(api) == []
        assert result.after.settings["enabled"] == "no"

    def test_remove_never_removes_or_switches_off_a_foreign_target(self) -> None:
        api = _device(targets=[dict(FOREIGN)])
        apply_traffic_flow(api, ON)
        api.ops.clear()
        result = apply_traffic_flow(api, OFF)
        assert result.matches, result.mismatches
        assert _targets(api) == [dict(FOREIGN)]
        assert result.after.foreign_targets == 1
        # Somebody else is still exporting: the switch stays as it was.
        assert not [op for op in api.ops if op[1] == SETTINGS]
        assert result.after.settings["enabled"] == "yes"

    def test_remove_with_no_identity_removes_nothing(self) -> None:
        """"We do not know which target is ours" must mean none, not all."""
        api = _device(targets=[{".id": "*1", **OURS}, dict(FOREIGN)])
        unknown = TrafficFlowConfig(
            settings={"enabled": "no"}, ipfix={}, target=None, identity=None
        )
        result = apply_traffic_flow(api, unknown)
        assert api.ops == []
        assert len(_targets(api)) == 2 and result.after.foreign_targets == 2
        for empty in (None, {}):
            assert not is_our_target({"dst-address": "10.20.0.1", "port": 2055}, empty)

    def test_remove_on_a_router_that_never_had_it_is_a_verified_no_op(self) -> None:
        api = _device()
        result = apply_traffic_flow(api, OFF)
        assert result.matches and result.writes == ()


class TestPlanIsPure:
    def test_plan_does_not_touch_the_device(self) -> None:
        api = _device()
        state = read_traffic_flow(api, identity=IDENTITY)
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
        before = await adapter.read_traffic_flow(mikrotik_creds, identity=IDENTITY)
        assert before.settings["enabled"] == "no"
        patch_connect(api)
        result = await adapter.apply_traffic_flow(mikrotik_creds, ON)
        assert result.matches
        assert api.closed

    async def test_device_error_is_wrapped(self, patch_connect, mikrotik_creds) -> None:
        api = _Api(missing_menus={("system", "resource")})
        patch_connect(api)
        with pytest.raises(MikroTikDeviceError):
            await MikroTikAdapter().read_traffic_flow(mikrotik_creds, identity=IDENTITY)

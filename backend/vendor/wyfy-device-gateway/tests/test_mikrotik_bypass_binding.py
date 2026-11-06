"""The session bypass written at sign-in: one ``/ip hotspot ip-binding
type=bypassed comment=cloudguest-authmac`` row, added only where the
router's own authorized-MAC poll would add it -- against a fake RouterOS API.

Each test asserts what the fake device's tables hold afterwards. The router's
script stays the reconciler, so the properties that matter are the ones that
keep this write indistinguishable from the script's own: never a second row
for a MAC, never a row touched that this call did not add, and nothing at all
under a live hotspot session.
"""

from __future__ import annotations

from typing import Any

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikConnectionError,
    MikroTikDeviceError,
)

_BINDING = ("ip", "hotspot", "ip-binding")
_ACTIVE = ("ip", "hotspot", "active")
_HOST = ("ip", "hotspot", "host")
_SCHEDULER = ("system", "scheduler")
MAC = "02:00:00:00:00:99"
OTHER = "02:00:00:00:00:02"
TAG = "cloudguest-authmac"


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


_ENABLED = ({".id": "*C1", "name": "cloudguest-heartbeat-sched", "disabled": False},
            {".id": "*C2", "name": "cloudguest-authmac-sched", "disabled": False})


def _api(
    *, bindings=(), active=(), hosts=(), hotspot=True, schedulers=_ENABLED,
    **kwargs: Any,
) -> _Api:
    return _Api(
        menus={
            ("ip", "hotspot"): [{".id": "*1", "name": "hs1"}] if hotspot else [],
            _SCHEDULER: [dict(r) for r in schedulers],
            _BINDING: [dict(r) for r in bindings],
            _ACTIVE: [dict(r) for r in active],
            _HOST: [dict(r) for r in hosts],
        },
        **kwargs,
    )


async def _ensure(patch_connect, creds, api, mac=MAC):
    patch_connect(api)
    return await MikroTikAdapter().ensure_hotspot_bypass_binding(
        creds, mac_address=mac
    )


def _rows(api: FakeRouterOSApi, path) -> list[dict]:
    return list(api.path(*path))


class TestAdd:
    async def test_adds_exactly_the_row_the_routers_own_poll_adds(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(
            bindings=[{".id": "*B1", "mac-address": OTHER, "type": "bypassed",
                       "comment": "venue AP"}],
        )
        result = await _ensure(patch_connect, mikrotik_creds, api,
                               mac="02-00-00-00-00-99")

        assert result.outcome == "created" and result.created
        # The script's add, field for field: no `disabled`, no `server`, no
        # `place-before`, and the router's own spelling of the MAC.
        assert api.add_calls == [
            (_BINDING, {"mac-address": MAC, "type": "bypassed", "comment": TAG})
        ]
        bindings = _rows(api, _BINDING)
        assert [r[".id"] for r in bindings] == ["*B1", result.binding_id]
        assert bindings[0] == {".id": "*B1", "mac-address": OTHER,
                               "type": "bypassed", "comment": "venue AP"}
        assert api.closed

    async def test_the_only_write_is_one_add(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(hosts=[{".id": "*H1", "mac-address": MAC, "bypassed": False}])
        await _ensure(patch_connect, mikrotik_creds, api)
        assert [(op, path) for op, path, _ in api.ops] == [("add", _BINDING)]
        # The unauthorised host row is read, never removed.
        assert [r[".id"] for r in _rows(api, _HOST)] == ["*H1"]

    @pytest.mark.parametrize(
        ("hosts", "expected"),
        [
            ([], "absent"),
            ([{".id": "*H1", "mac-address": MAC, "bypassed": True}], "bypassed"),
            ([{".id": "*H1", "mac-address": MAC, "bypassed": False}], "pending"),
            ([{".id": "*H1", "mac-address": OTHER, "bypassed": False}], "absent"),
        ],
    )
    async def test_the_host_row_is_reported_as_read(
        self, patch_connect, mikrotik_creds, hosts, expected
    ) -> None:
        result = await _ensure(patch_connect, mikrotik_creds, _api(hosts=hosts))
        assert result.host_state == expected

    async def test_an_unreadable_host_table_does_not_undo_the_binding(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(missing_menus={_HOST})
        result = await _ensure(patch_connect, mikrotik_creds, api)
        assert result.created and result.host_state is None
        assert len(_rows(api, _BINDING)) == 1


class TestNothingIsWritten:
    async def test_twice_writes_nothing_the_second_time(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        first = await _ensure(patch_connect, mikrotik_creds, api)
        writes = len(api.ops)
        second = await _ensure(patch_connect, mikrotik_creds, api)
        assert len(api.ops) == writes
        assert second.outcome == "already_bound"
        assert second.existing_bindings == (f"bypassed:{TAG}",)
        assert [r[".id"] for r in _rows(api, _BINDING)] == [first.binding_id]

    @pytest.mark.parametrize(
        "row",
        [
            # An operator's own bypass for the device (the venue's AP).
            {"mac-address": MAC, "type": "bypassed", "comment": "venue AP"},
            # One with no comment at all.
            {"mac-address": MAC, "type": "bypassed"},
            # A device rule's block. A bypass beside it would be a second
            # opinion about a device the venue has cut off.
            {"mac-address": MAC, "type": "blocked",
             "comment": "cloudguest-devblock:0f0f0f0f-0000-4000-8000-000000000001"},
            # A trusted-device bypass.
            {"mac-address": MAC, "type": "bypassed", "comment": "cloudguest-trusted:x"},
            # A disabled row still answers `find where mac-address=`.
            {"mac-address": MAC, "type": "bypassed", "comment": TAG, "disabled": True},
            # The router's spelling is not assumed.
            {"mac-address": "02-00-00-00-00-99", "type": "regular", "comment": "x"},
        ],
    )
    async def test_any_existing_binding_for_the_mac_is_left_exactly_as_found(
        self, patch_connect, mikrotik_creds, row
    ) -> None:
        before = {".id": "*B1", **row}
        api = _api(bindings=[before])
        result = await _ensure(patch_connect, mikrotik_creds, api)
        assert result.outcome == "already_bound"
        assert result.binding_id is None
        assert api.ops == []
        assert _rows(api, _BINDING) == [before]

    async def test_a_live_hotspot_session_is_never_bound_underneath(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(active=[{".id": "*S1", "mac-address": MAC, "user": "guest"}])
        result = await _ensure(patch_connect, mikrotik_creds, api)
        assert result.outcome == "active_session"
        assert api.ops == []
        assert _rows(api, _BINDING) == []
        assert [r[".id"] for r in _rows(api, _ACTIVE)] == ["*S1"]

    async def test_someone_elses_session_does_not_stop_this_mac(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(active=[{".id": "*S1", "mac-address": OTHER, "user": "guest"}])
        result = await _ensure(patch_connect, mikrotik_creds, api)
        assert result.created

    async def test_a_router_running_no_hotspot_gets_no_write(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(hotspot=False)
        result = await _ensure(patch_connect, mikrotik_creds, api)
        assert result.outcome == "no_hotspot" and result.hotspot_servers == 0
        assert api.ops == []

    @pytest.mark.parametrize(
        "schedulers",
        [
            # Never provisioned with the loop at all.
            [],
            [{".id": "*C1", "name": "cloudguest-heartbeat-sched", "disabled": False}],
            # Switched off on purpose by the venue's operator.
            [{".id": "*C2", "name": "cloudguest-authmac-sched", "disabled": True}],
            # RouterOS reports booleans as strings over some transports.
            [{".id": "*C2", "name": "cloudguest-authmac-sched", "disabled": "true"}],
        ],
    )
    async def test_no_enabled_reconciler_means_no_binding_nothing_would_remove_it(
        self, patch_connect, mikrotik_creds, schedulers
    ) -> None:
        api = _api(schedulers=schedulers)
        result = await _ensure(patch_connect, mikrotik_creds, api)
        assert result.outcome == "no_reconciler" and not result.created
        assert api.ops == []
        assert _rows(api, _BINDING) == []

    async def test_not_a_mac_is_refused_before_any_connection(
        self, patch_connect, mikrotik_creds
    ) -> None:
        patch_connect(AssertionError("must not connect"))
        with pytest.raises(ValueError):
            await MikroTikAdapter().ensure_hotspot_bypass_binding(
                mikrotik_creds, mac_address="UNKNOWN"
            )


class TestRaceWithTheRoutersOwnPoll:
    async def test_a_row_the_poll_added_in_between_wins_and_ours_is_taken_back(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        binding_path = api.path(*_BINDING)
        real_add = type(binding_path).add

        def _add_after_the_poll(self, **fields: Any) -> str:
            if self._segments == _BINDING:
                # The scheduler's add lands first, between our read and ours.
                self._rows.append({".id": "*SCHED", "mac-address": MAC,
                                   "type": "bypassed", "comment": TAG})
            return real_add(self, **fields)

        type(binding_path).add = _add_after_the_poll  # type: ignore[method-assign]
        try:
            result = await _ensure(patch_connect, mikrotik_creds, api)
        finally:
            type(binding_path).add = real_add  # type: ignore[method-assign]

        assert result.outcome == "raced" and result.binding_id is None
        assert [r[".id"] for r in _rows(api, _BINDING)] == ["*SCHED"]
        # Only the row this call added was removed, by the id the add returned.
        removed = [arg for op, path, arg in api.ops if op == "remove"]
        assert len(removed) == 1 and "*SCHED" not in str(removed[0])


class TestFailures:
    async def test_a_refused_add_is_a_device_error_and_leaves_nothing(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        path_type = type(api.path(*_BINDING))
        real_add = path_type.add

        def _refuse(self, **fields: Any) -> str:
            raise LibRouterosError("failure: not enough permissions")

        path_type.add = _refuse  # type: ignore[method-assign]
        try:
            with pytest.raises(MikroTikDeviceError):
                await _ensure(patch_connect, mikrotik_creds, api)
        finally:
            path_type.add = real_add  # type: ignore[method-assign]
        assert _rows(api, _BINDING) == []
        assert api.closed

    async def test_an_unreachable_router_is_a_connection_error(
        self, patch_connect, mikrotik_creds
    ) -> None:
        patch_connect(OSError("timed out"))
        with pytest.raises(MikroTikConnectionError):
            await MikroTikAdapter().ensure_hotspot_bypass_binding(
                mikrotik_creds, mac_address=MAC
            )

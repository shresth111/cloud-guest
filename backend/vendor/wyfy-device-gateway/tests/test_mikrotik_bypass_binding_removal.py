"""Taking a session bypass off a router: the read that lists
``cloudguest-authmac`` bindings and the removal of one of them by ``.id`` --
against a fake RouterOS API.

The properties that matter are the ones that keep this from ever touching a
row that is not this platform's: the listing shows only rows whose comment
is exactly the tag, and the removal re-reads the row and refuses if it is no
longer the one that was listed.
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


def _ours(row_id: str = "*B1", mac: str = MAC, **extra: Any) -> dict[str, Any]:
    return {".id": row_id, "mac-address": mac, "type": "bypassed", "comment": TAG,
            **extra}


def _api(
    *, bindings=(), active=(), hosts=(), hotspot=True, schedulers=(), **kwargs: Any
) -> FakeRouterOSApi:
    return FakeRouterOSApi(
        menus={
            ("ip", "hotspot"): [{".id": "*1", "name": "hs1"}] if hotspot else [],
            _SCHEDULER: [dict(r) for r in schedulers],
            _BINDING: [dict(r) for r in bindings],
            _ACTIVE: [dict(r) for r in active],
            _HOST: [dict(r) for r in hosts],
        },
        **kwargs,
    )


async def _read(patch_connect, creds, api):
    patch_connect(api)
    return await MikroTikAdapter().read_hotspot_bypass_bindings(creds)


async def _remove(patch_connect, creds, api, binding_id="*B1", mac=MAC, **kwargs: Any):
    patch_connect(api)
    return await MikroTikAdapter().remove_hotspot_bypass_binding(
        creds, binding_id=binding_id, mac_address=mac, **kwargs
    )


def _rows(api: FakeRouterOSApi, path) -> list[dict]:
    return list(api.path(*path))


class TestRead:
    async def test_lists_only_rows_tagged_exactly(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[
            _ours("*B1", "02-00-00-00-00-99"),
            _ours("*B2", OTHER, disabled=True),
            {".id": "*B3", "mac-address": MAC, "type": "bypassed", "comment": "venue AP"},
            {".id": "*B4", "mac-address": MAC, "type": "bypassed"},
            {".id": "*B5", "mac-address": MAC, "type": "bypassed",
             "comment": "cloudguest-trusted:x"},
            {".id": "*B6", "mac-address": MAC, "type": "blocked",
             "comment": "cloudguest-devblock:0f0f0f0f-0000-4000-8000-000000000001"},
            # Near misses: a prefix, a suffix, different case.
            {".id": "*B7", "mac-address": MAC, "type": "bypassed",
             "comment": "cloudguest-authmac-old"},
            {".id": "*B8", "mac-address": MAC, "type": "bypassed",
             "comment": "keep cloudguest-authmac"},
            {".id": "*B9", "mac-address": MAC, "type": "bypassed",
             "comment": "CloudGuest-AuthMac"},
        ])
        snapshot = await _read(patch_connect, mikrotik_creds, api)
        assert [(r.binding_id, r.mac_address, r.disabled) for r in snapshot.bindings] == [
            ("*B1", MAC, False),
            ("*B2", OTHER, True),
        ]
        assert snapshot.unreadable == 0
        assert api.ops == [], "a read writes nothing"
        assert api.closed

    @pytest.mark.parametrize(
        ("schedulers", "expected"),
        [
            ([], False),
            ([{"name": "cloudguest-heartbeat-sched", "disabled": False}], False),
            ([{"name": "cloudguest-authmac-sched", "disabled": True}], False),
            ([{"name": "cloudguest-authmac-sched", "disabled": False}], True),
        ],
    )
    async def test_reports_whether_the_routers_own_loop_runs_and_lists_either_way(
        self, patch_connect, mikrotik_creds, schedulers, expected
    ) -> None:
        api = _api(bindings=[_ours()], schedulers=schedulers)
        snapshot = await _read(patch_connect, mikrotik_creds, api)
        assert snapshot.reconciler_enabled is expected
        assert len(snapshot.bindings) == 1

    async def test_a_tagged_row_with_no_readable_mac_is_counted_not_listed(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[_ours("*B1", "not-a-mac"), _ours("*B2")])
        snapshot = await _read(patch_connect, mikrotik_creds, api)
        assert [r.binding_id for r in snapshot.bindings] == ["*B2"]
        assert snapshot.unreadable == 1

    async def test_an_unreachable_router_is_a_connection_error(
        self, patch_connect, mikrotik_creds
    ) -> None:
        patch_connect(OSError("timed out"))
        with pytest.raises(MikroTikConnectionError):
            await MikroTikAdapter().read_hotspot_bypass_bindings(mikrotik_creds)

    async def test_an_unreadable_binding_table_is_a_device_error(
        self, patch_connect, mikrotik_creds
    ) -> None:
        with pytest.raises(MikroTikDeviceError):
            await _read(patch_connect, mikrotik_creds, _api(missing_menus={_BINDING}))


class TestRemove:
    async def test_removes_the_one_row_and_nothing_else(
        self, patch_connect, mikrotik_creds
    ) -> None:
        keep = [
            {".id": "*B2", "mac-address": OTHER, "type": "bypassed", "comment": TAG},
            {".id": "*B3", "mac-address": OTHER, "type": "bypassed",
             "comment": "venue AP"},
        ]
        api = _api(bindings=[_ours(), *keep])
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.removed
        assert _rows(api, _BINDING) == keep
        assert [(op, path) for op, path, _ in api.ops] == [("remove", _BINDING)]
        assert api.add_calls == [] and api.update_calls == []

    async def test_a_row_that_is_already_gone_is_not_an_error(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[_ours("*B2", OTHER)])
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.outcome == "gone" and api.ops == []

    @pytest.mark.parametrize(
        "now",
        [
            # An operator took the row over and re-labelled it.
            {".id": "*B1", "mac-address": MAC, "type": "bypassed", "comment": "venue AP"},
            {".id": "*B1", "mac-address": MAC, "type": "bypassed"},
            # The .id now names a different device's row.
            {".id": "*B1", "mac-address": OTHER, "type": "bypassed", "comment": TAG},
        ],
    )
    async def test_a_row_that_is_no_longer_the_one_listed_is_left_alone(
        self, patch_connect, mikrotik_creds, now
    ) -> None:
        api = _api(bindings=[now], hosts=[{".id": "*H1", "mac-address": MAC,
                                           "bypassed": True}])
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.outcome == "changed"
        assert api.ops == []
        assert _rows(api, _BINDING) == [now]

    async def test_works_on_a_router_with_no_scheduler_at_all(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[_ours()], schedulers=[])
        assert (await _remove(patch_connect, mikrotik_creds, api)).removed
        assert _rows(api, _BINDING) == []

    async def test_not_a_mac_is_refused_before_any_connection(
        self, patch_connect, mikrotik_creds
    ) -> None:
        patch_connect(AssertionError("must not connect"))
        with pytest.raises(ValueError):
            await MikroTikAdapter().remove_hotspot_bypass_binding(
                mikrotik_creds, binding_id="*B1", mac_address="UNKNOWN"
            )

    async def test_a_refused_remove_is_a_device_error(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[_ours()])
        path_type = type(api.path(*_BINDING))
        real = path_type.remove

        def _refuse(self, *ids: Any) -> None:
            raise LibRouterosError("failure: not enough permissions")

        path_type.remove = _refuse  # type: ignore[method-assign]
        try:
            with pytest.raises(MikroTikDeviceError):
                await _remove(patch_connect, mikrotik_creds, api)
        finally:
            path_type.remove = real  # type: ignore[method-assign]
        assert len(_rows(api, _BINDING)) == 1 and api.closed


class TestTheHostRow:
    async def test_a_host_still_bypassed_after_the_removal_is_dropped(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(
            bindings=[_ours()],
            hosts=[{".id": "*H1", "mac-address": MAC, "bypassed": True},
                   {".id": "*H2", "mac-address": OTHER, "bypassed": True}],
        )
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert (result.host_before, result.host_after) == ("bypassed", "bypassed")
        assert result.hosts_removed == 1
        assert [r[".id"] for r in _rows(api, _HOST)] == ["*H2"]
        # The binding goes first: the host is only dropped once nothing
        # would re-create it bypassed.
        assert [(op, path) for op, path, _ in api.ops] == [
            ("remove", _BINDING), ("remove", _HOST)]

    async def test_it_is_only_read_when_asked_not_to_drop_it(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[_ours()],
                   hosts=[{".id": "*H1", "mac-address": MAC, "bypassed": True}])
        result = await _remove(patch_connect, mikrotik_creds, api,
                               drop_bypassed_host=False)
        assert result.removed and result.host_after == "bypassed"
        assert result.hosts_removed == 0
        assert len(_rows(api, _HOST)) == 1

    @pytest.mark.parametrize(
        ("hosts", "state"),
        [
            ([], "absent"),
            ([{".id": "*H1", "mac-address": MAC, "bypassed": False}], "unbypassed"),
        ],
    )
    async def test_a_host_the_router_already_dealt_with_is_left(
        self, patch_connect, mikrotik_creds, hosts, state
    ) -> None:
        api = _api(bindings=[_ours()], hosts=hosts)
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.host_after == state and result.hosts_removed == 0
        assert _rows(api, _HOST) == hosts

    async def test_another_binding_for_the_mac_keeps_its_host(
        self, patch_connect, mikrotik_creds
    ) -> None:
        """The device is still bypassed -- by a row that is not ours. Its
        host is that row's business."""
        operator = {".id": "*B2", "mac-address": MAC, "type": "bypassed",
                    "comment": "venue AP"}
        api = _api(bindings=[_ours(), operator],
                   hosts=[{".id": "*H1", "mac-address": MAC, "bypassed": True}])
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.removed and result.other_bindings == ("bypassed:venue AP",)
        assert result.hosts_removed == 0
        assert _rows(api, _BINDING) == [operator]
        assert len(_rows(api, _HOST)) == 1

    async def test_a_live_hotspot_session_keeps_its_host(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(
            bindings=[_ours()],
            active=[{".id": "*S1", "mac-address": MAC, "user": "guest"}],
            hosts=[{".id": "*H1", "mac-address": MAC, "bypassed": True,
                    "authorized": True}],
        )
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.removed and result.active_session
        assert result.hosts_removed == 0
        assert len(_rows(api, _HOST)) == 1 and len(_rows(api, _ACTIVE)) == 1

    async def test_an_unreadable_host_table_does_not_undo_the_removal(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(bindings=[_ours()], missing_menus={_HOST})
        result = await _remove(patch_connect, mikrotik_creds, api)
        assert result.removed and result.host_after is None
        assert _rows(api, _BINDING) == []

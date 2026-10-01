"""A durable per-device block: ``/ip hotspot ip-binding type=blocked`` plus
the device's live session removed -- against a fake RouterOS API.

Each test asserts what the fake device's tables hold afterwards, not that a
method was called: the defect this closes is a block that returned success
while the router kept forwarding for the device.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import (
    DEVICE_BLOCK_MARKER_PREFIX,
    MikroTikAdapter,
    MikroTikDeviceError,
)

_BINDING = ("ip", "hotspot", "ip-binding")
_ACTIVE = ("ip", "hotspot", "active")
_HOST = ("ip", "hotspot", "host")
MAC = "02:00:00:00:00:99"
OTHER = "AA:BB:CC:DD:EE:02"


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


def _marker() -> str:
    return f"{DEVICE_BLOCK_MARKER_PREFIX}{uuid.uuid4()}"


def _api(*, bindings=(), active=(), hosts=(), hotspot=True) -> _Api:
    return _Api(
        menus={
            ("ip", "hotspot"): [{".id": "*1", "name": "hs1"}] if hotspot else [],
            _BINDING: [dict(r) for r in bindings],
            _ACTIVE: [dict(r) for r in active],
            _HOST: [dict(r) for r in hosts],
            ("radius", "incoming"): [{"accept": False, "port": "3799"}],
        }
    )


async def _block(patch_connect, creds, api, marker, mac=MAC):
    patch_connect(api)
    return await MikroTikAdapter().block_hotspot_device(
        creds, mac_address=mac, marker=marker
    )


async def _unblock(patch_connect, creds, api, marker, mac=MAC):
    patch_connect(api)
    return await MikroTikAdapter().unblock_hotspot_device(
        creds, mac_address=mac, marker=marker
    )


def _rows(api: FakeRouterOSApi, path) -> list[dict]:
    return list(api.path(*path))


class TestBlock:
    async def test_writes_a_blocked_binding_and_ends_the_live_session(
        self, patch_connect, mikrotik_creds
    ) -> None:
        marker = _marker()
        api = _api(
            bindings=[{".id": "*B1", "mac-address": "AA:AA:AA:AA:AA:01",
                       "type": "bypassed", "comment": "venue AP"}],
            active=[{".id": "*S1", "mac-address": MAC, "user": "+919999999999"},
                    {".id": "*S2", "mac-address": OTHER, "user": "+918888888888"}],
            hosts=[{".id": "*H1", "mac-address": MAC}, {".id": "*H2", "mac-address": OTHER}],
        )
        result = await _block(patch_connect, mikrotik_creds, api, marker,
                              mac="02-00-00-00-00-99")

        bindings = _rows(api, _BINDING)
        assert bindings[0]["mac-address"] == MAC
        assert bindings[0]["type"] == "blocked"
        assert bindings[0]["comment"] == marker
        assert bindings[1][".id"] == "*B1", "someone else's binding is untouched"
        assert [r[".id"] for r in _rows(api, _ACTIVE)] == ["*S2"]
        assert [r[".id"] for r in _rows(api, _HOST)] == ["*H2"]
        assert result.created and result.first_in_order
        assert result.sessions_removed == 1 and result.hosts_removed == 1
        assert result.still_active == 0
        # Placed ahead of the existing row, by .id.
        assert api.add_calls[0][1]["place-before"] == "*B1"

    async def test_blocking_twice_writes_nothing_the_second_time(
        self, patch_connect, mikrotik_creds
    ) -> None:
        marker = _marker()
        api = _api()
        first = await _block(patch_connect, mikrotik_creds, api, marker)
        writes = len(api.ops)
        second = await _block(patch_connect, mikrotik_creds, api, marker)
        assert len(api.ops) == writes
        assert second.binding_id == first.binding_id and not second.created
        assert len(_rows(api, _BINDING)) == 1

    async def test_the_session_bypass_for_this_mac_goes_other_bypasses_stay(
        self, patch_connect, mikrotik_creds
    ) -> None:
        marker = _marker()
        api = _api(bindings=[
            {".id": "*B1", "mac-address": MAC, "type": "bypassed",
             "comment": "cloudguest-authmac"},
            {".id": "*B2", "mac-address": MAC, "type": "bypassed",
             "comment": "cloudguest-trusted:abc"},
            {".id": "*B3", "mac-address": OTHER, "type": "bypassed",
             "comment": "cloudguest-authmac"},
        ])
        result = await _block(patch_connect, mikrotik_creds, api, marker)
        ids = [r[".id"] for r in _rows(api, _BINDING)]
        assert "*B1" not in ids
        assert "*B2" in ids and "*B3" in ids
        assert ids[0] == result.binding_id
        assert result.removed_bypass_ids == ("*B1",)
        assert result.other_bindings == ("bypassed:cloudguest-trusted:abc",)
        # The blocked row exists before the bypass is removed: never a moment
        # where the MAC is free.
        kinds = [op for op, path, _ in api.ops if path == _BINDING]
        assert kinds == ["add", "remove"]

    async def test_a_disabled_copy_of_our_row_is_replaced(
        self, patch_connect, mikrotik_creds
    ) -> None:
        marker = _marker()
        api = _api(bindings=[{".id": "*B1", "mac-address": MAC, "type": "blocked",
                              "comment": marker, "disabled": "true"}])
        result = await _block(patch_connect, mikrotik_creds, api, marker)
        rows = _rows(api, _BINDING)
        assert len(rows) == 1 and rows[0][".id"] == result.binding_id != "*B1"

    async def test_a_router_without_a_hotspot_gets_no_write(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(hotspot=False)
        result = await _block(patch_connect, mikrotik_creds, api, _marker())
        assert result.hotspot_servers == 0 and result.binding_id is None
        assert api.ops == []

    async def test_a_binding_that_does_not_read_back_raises(
        self, patch_connect, mikrotik_creds
    ) -> None:
        class _Ghost(_Api):
            def path(self, *segments: str):
                menu = super().path(*segments)
                if segments == _BINDING:
                    menu.add = lambda **fields: "*GHOST"  # type: ignore[method-assign]
                return menu

        api = _Ghost(menus=_api()._menus)
        with pytest.raises(MikroTikDeviceError):
            await _block(patch_connect, mikrotik_creds, api, _marker())

    async def test_place_before_refused_still_blocks_and_reports_position(
        self, patch_connect, mikrotik_creds
    ) -> None:
        class _NoPlace(_Api):
            def path(self, *segments: str):
                menu = super().path(*segments)
                if segments == _BINDING:
                    original = menu.add

                    def add(**fields: Any) -> str:
                        if "place-before" in fields:
                            raise LibRouterosError("unknown parameter place-before")
                        return original(**fields)

                    menu.add = add  # type: ignore[method-assign]
                return menu

        api = _NoPlace(menus=_api(bindings=[{".id": "*B1", "mac-address": OTHER,
                                             "type": "bypassed"}])._menus)
        result = await _block(patch_connect, mikrotik_creds, api, _marker())
        assert result.binding_id is not None
        assert result.first_in_order is False

    @pytest.mark.parametrize(
        ("mac", "marker"),
        [("not-a-mac", f"{DEVICE_BLOCK_MARKER_PREFIX}{uuid.uuid4()}"),
         (MAC, "cloudguest-authmac"), (MAC, "cloudguest-devblock:nope")],
    )
    async def test_bad_arguments_never_reach_the_router(
        self, patch_connect, mikrotik_creds, mac, marker
    ) -> None:
        api = _api()
        with pytest.raises(ValueError):
            await _block(patch_connect, mikrotik_creds, api, marker, mac=mac)
        assert api.ops == []


class TestUnblock:
    async def test_removes_exactly_our_binding(self, patch_connect, mikrotik_creds) -> None:
        marker, other_marker = _marker(), _marker()
        api = _api(bindings=[
            {".id": "*B2", "mac-address": MAC, "type": "bypassed",
             "comment": "cloudguest-trusted:abc"},
            {".id": "*B3", "mac-address": MAC, "type": "blocked", "comment": other_marker},
        ])
        await _block(patch_connect, mikrotik_creds, api, marker)
        result = await _unblock(patch_connect, mikrotik_creds, api, marker)
        assert len(result.removed_ids) == 1 and result.remaining == 0
        assert [r[".id"] for r in _rows(api, _BINDING)] == ["*B2", "*B3"]

    async def test_unblocking_what_is_not_there_is_clean(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        result = await _unblock(patch_connect, mikrotik_creds, api, _marker())
        assert result.removed_ids == () and result.remaining == 0
        assert api.ops == []

    async def test_a_binding_that_survives_removal_is_reported(
        self, patch_connect, mikrotik_creds
    ) -> None:
        marker = _marker()

        class _Sticky(_Api):
            def path(self, *segments: str):
                menu = super().path(*segments)
                if segments == _BINDING:
                    menu.remove = lambda *ids: None  # type: ignore[method-assign]
                return menu

        api = _Sticky(menus=_api(bindings=[{".id": "*B1", "mac-address": MAC,
                                            "type": "blocked", "comment": marker}])._menus)
        result = await _unblock(patch_connect, mikrotik_creds, api, marker)
        assert result.remaining == 1

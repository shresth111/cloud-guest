"""Keeping one device on its address: ``/ip dhcp-server lease make-static``
with a read-back, against a fake RouterOS API.

Each test asserts what the fake lease table holds afterwards (and which
writes were issued), not merely that a method returned: a firewall rule by
address is only as good as the lease under it.
"""

from __future__ import annotations

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikDeviceError,
    MikroTikLeaseConflictError,
    MikroTikLeaseNotFoundError,
)

_LEASE = ("ip", "dhcp-server", "lease")
PRINTER = "AA:BB:CC:00:00:20"
OTHER = "AA:BB:CC:00:00:21"


def _api(*rows: dict) -> FakeRouterOSApi:
    return FakeRouterOSApi(menus={_LEASE: [dict(r) for r in rows]})


def _dyn(mac: str, address: str, rid: str = "*1", **extra) -> dict:
    return {
        ".id": rid,
        "mac-address": mac,
        "address": address,
        "active-address": address,
        "dynamic": True,
        "status": "bound",
        "host-name": "printer",
        "server": "dhcp-lan",
        **extra,
    }


def _writes(api: FakeRouterOSApi) -> list:
    return [op for op in api.ops if op[0] != "command"]


async def _keep(patch_connect, creds, api, mac=PRINTER, address="192.168.88.20"):
    patch_connect(api)
    return await MikroTikAdapter().keep_dhcp_lease_address(
        creds, mac_address=mac, address=address
    )


async def test_read_dhcp_leases_reports_dynamic_and_static(patch_connect, mikrotik_creds):
    api = _api(
        _dyn(PRINTER, "192.168.88.20"),
        {".id": "*2", "mac-address": OTHER.lower(), "address": "192.168.88.30", "dynamic": "false"},
        {".id": "*3", "address": "192.168.88.40"},  # no MAC: skipped, not guessed
    )
    patch_connect(api)
    leases = await MikroTikAdapter().read_dhcp_leases(mikrotik_creds)
    by_mac = {lease.mac_address: lease for lease in leases}
    assert set(by_mac) == {PRINTER, OTHER}
    assert by_mac[PRINTER].dynamic is True
    assert by_mac[PRINTER].host_name == "printer"
    assert by_mac[OTHER].dynamic is False
    assert by_mac[OTHER].address == "192.168.88.30"
    assert api.closed


async def test_read_dhcp_leases_raises_rather_than_answering_empty(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(missing_menus={_LEASE})
    patch_connect(api)
    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().read_dhcp_leases(mikrotik_creds)


async def test_dynamic_lease_is_made_static_and_read_back(patch_connect, mikrotik_creds):
    api = _api(_dyn(OTHER, "192.168.88.21", rid="*7"), _dyn(PRINTER, "192.168.88.20", rid="*9"))
    result = await _keep(patch_connect, mikrotik_creds, api)
    assert result.changed is True
    assert result.lease.dynamic is False
    assert result.lease.address == "192.168.88.20"
    assert _writes(api) == [("make-static", _LEASE, "*9")]
    rows = {r[".id"]: r for r in api.path(*_LEASE)}
    assert rows["*9"]["dynamic"] is False
    # The other device's lease is untouched.
    assert rows["*7"]["dynamic"] is True
    assert api.closed


async def test_already_static_on_that_address_writes_nothing(patch_connect, mikrotik_creds):
    api = _api({**_dyn(PRINTER, "192.168.88.20"), "dynamic": False})
    result = await _keep(patch_connect, mikrotik_creds, api)
    assert result.changed is False
    assert result.lease.dynamic is False
    assert _writes(api) == []


async def test_second_call_is_a_no_op(patch_connect, mikrotik_creds):
    api = _api(_dyn(PRINTER, "192.168.88.20"))
    first = await _keep(patch_connect, mikrotik_creds, api)
    second = await _keep(patch_connect, mikrotik_creds, api)
    assert (first.changed, second.changed) == (True, False)
    assert len(_writes(api)) == 1


async def test_mac_is_matched_in_any_case_and_separator(patch_connect, mikrotik_creds):
    api = _api(_dyn("aa:bb:cc:00:00:20", "192.168.88.20"))
    result = await _keep(
        patch_connect, mikrotik_creds, api, mac="aa-bb-cc-00-00-20"
    )
    assert result.changed is True


async def test_no_lease_for_the_device_is_refused_without_a_write(
    patch_connect, mikrotik_creds
):
    api = _api(_dyn(OTHER, "192.168.88.21"))
    with pytest.raises(MikroTikLeaseNotFoundError):
        await _keep(patch_connect, mikrotik_creds, api)
    assert _writes(api) == []


async def test_lease_that_moved_is_refused_with_the_new_address(
    patch_connect, mikrotik_creds
):
    api = _api(_dyn(PRINTER, "192.168.88.55"))
    with pytest.raises(MikroTikLeaseConflictError) as info:
        await _keep(patch_connect, mikrotik_creds, api)
    assert info.value.reason == "moved"
    assert info.value.current_address == "192.168.88.55"
    assert _writes(api) == []


async def test_reservation_elsewhere_is_refused_not_overwritten(
    patch_connect, mikrotik_creds
):
    api = _api({**_dyn(PRINTER, "192.168.88.99"), "dynamic": False})
    with pytest.raises(MikroTikLeaseConflictError) as info:
        await _keep(patch_connect, mikrotik_creds, api)
    assert info.value.reason == "reserved_elsewhere"
    assert info.value.current_address == "192.168.88.99"
    assert _writes(api) == []


async def test_a_make_static_the_router_ignores_is_not_reported_as_kept(
    patch_connect, mikrotik_creds
):
    api = _api(_dyn(PRINTER, "192.168.88.20"))
    api.silently_ignore_commands.add(("make-static", _LEASE))
    with pytest.raises(MikroTikDeviceError) as info:
        await _keep(patch_connect, mikrotik_creds, api)
    assert not isinstance(info.value, MikroTikLeaseConflictError)
    assert "read back" in info.value.detail


async def test_router_refusal_becomes_a_device_error(patch_connect, mikrotik_creds):
    class _Refusing(FakeRouterOSApi):
        def path(self, *segments):
            p = super().path(*segments)
            original = p.__call__

            class _P:
                def __iter__(self_inner):
                    return iter(p)

                def __call__(self_inner, cmd=None, **kw):
                    if cmd == "make-static":
                        raise LibRouterosError("failure: already have static lease")
                    return original(cmd, **kw)

            return _P()

    api = _Refusing(menus={_LEASE: [_dyn(PRINTER, "192.168.88.20")]})
    with pytest.raises(MikroTikDeviceError) as info:
        await _keep(patch_connect, mikrotik_creds, api)
    assert "already have static lease" in info.value.detail
    assert api.closed


@pytest.mark.parametrize("bad", ["", "not-a-mac"])
async def test_bad_mac_is_refused_before_connecting(patch_connect, mikrotik_creds, bad):
    patch_connect(RuntimeError("must not connect"))
    with pytest.raises(ValueError):
        await MikroTikAdapter().keep_dhcp_lease_address(
            mikrotik_creds, mac_address=bad, address="192.168.88.20"
        )


async def test_bad_address_is_refused_before_connecting(patch_connect, mikrotik_creds):
    patch_connect(RuntimeError("must not connect"))
    with pytest.raises(ValueError):
        await MikroTikAdapter().keep_dhcp_lease_address(
            mikrotik_creds, mac_address=PRINTER, address="192.168.88.0/24"
        )

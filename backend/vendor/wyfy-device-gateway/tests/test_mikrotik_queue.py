"""Queue management (QoS/bandwidth shaping) -- ported from
``queue_management/device_adapters.py``."""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import QueueDeviceStatus
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError


@pytest.mark.asyncio
async def test_create_simple_queue_formats_rates_and_burst_fields(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    device_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="cloudguest-q1",
        target="10.0.0.5/32",
        download_rate_kbps=5000,
        upload_rate_kbps=1000,
        burst_download_kbps=8000,
        burst_upload_kbps=2000,
        burst_threshold_kbps=4000,
        burst_time_seconds=8,
        priority=3,
    )

    (call_segments, fields) = api.add_calls[-1]
    assert call_segments == ("queue", "simple")
    assert fields["name"] == "cloudguest-q1"
    assert fields["target"] == "10.0.0.5/32"
    assert fields["max-limit"] == "1000k/5000k"
    assert fields["burst-limit"] == "2000k/8000k"
    assert fields["burst-threshold"] == "4000k/4000k"
    assert fields["burst-time"] == "8/8"
    assert fields["priority"] == "3"
    assert device_id == "*1"
    assert api.closed is True


@pytest.mark.asyncio
async def test_create_simple_queue_without_burst_omits_burst_fields(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.create_simple_queue(
        mikrotik_creds,
        name="q2",
        target="10.0.0.6/32",
        download_rate_kbps=2000,
        upload_rate_kbps=512,
    )
    (_, fields) = api.add_calls[-1]
    assert "burst-limit" not in fields
    assert "burst-threshold" not in fields
    assert "burst-time" not in fields


@pytest.mark.asyncio
async def test_update_simple_queue_changes_existing_row(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="q1",
        target="10.0.0.5/32",
        download_rate_kbps=1000,
        upload_rate_kbps=500,
    )

    await adapter.update_simple_queue(
        mikrotik_creds,
        device_queue_id=device_id,
        download_rate_kbps=9000,
        upload_rate_kbps=3000,
        priority=1,
    )
    row = next(r for r in api._menus[("queue", "simple")] if r[".id"] == device_id)
    assert row["max-limit"] == "3000k/9000k"
    assert row["priority"] == "1"


@pytest.mark.asyncio
async def test_delete_simple_queue_removes_row(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="q1",
        target="10.0.0.5/32",
        download_rate_kbps=1000,
        upload_rate_kbps=500,
    )
    await adapter.delete_simple_queue(mikrotik_creds, device_queue_id=device_id)
    assert all(r[".id"] != device_id for r in api._menus[("queue", "simple")])


@pytest.mark.asyncio
async def test_create_simple_queue_connection_failure_raises(patch_connect, mikrotik_creds):
    from librouteros.exceptions import LibRouterosError

    patch_connect(LibRouterosError("connection refused"))
    adapter = MikroTikAdapter()
    with pytest.raises(MikroTikDeviceError):
        await adapter.create_simple_queue(
            mikrotik_creds,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )


@pytest.mark.asyncio
async def test_create_queue_tree(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    device_id = await adapter.create_queue_tree(
        mikrotik_creds,
        name="org-ceiling",
        parent="ether1",
        packet_mark="org-mark",
        max_limit_kbps=100000,
        priority=4,
        queue_type_name="fair-share",
    )
    row = next(r for r in api._menus[("queue", "tree")] if r[".id"] == device_id)
    assert row["parent"] == "ether1"
    assert row["packet-mark"] == "org-mark"
    assert row["max-limit"] == "100000k"
    assert row["priority"] == "4"
    assert row["queue"] == "fair-share"


@pytest.mark.asyncio
async def test_apply_pcq(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    device_id = await adapter.apply_pcq(
        mikrotik_creds, name="fair-share", rate_kbps=50000, classifier="src-address"
    )
    row = next(r for r in api._menus[("queue", "type")] if r[".id"] == device_id)
    assert row["kind"] == "pcq"
    assert row["pcq-rate"] == "50000k"
    assert row["pcq-classifier"] == "src-address"


@pytest.mark.asyncio
async def test_set_priority(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="q1",
        target="10.0.0.5/32",
        download_rate_kbps=1000,
        upload_rate_kbps=500,
    )
    await adapter.set_priority(mikrotik_creds, device_queue_id=device_id, priority=2)
    row = next(r for r in api._menus[("queue", "simple")] if r[".id"] == device_id)
    assert row["priority"] == "2"


@pytest.mark.asyncio
async def test_assign_queue_to_target(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="q1",
        target="10.0.0.5/32",
        download_rate_kbps=1000,
        upload_rate_kbps=500,
    )
    await adapter.assign_queue_to_target(
        mikrotik_creds, device_queue_id=device_id, target="10.0.0.99/32"
    )
    row = next(r for r in api._menus[("queue", "simple")] if r[".id"] == device_id)
    assert row["target"] == "10.0.0.99/32"


@pytest.mark.asyncio
async def test_remove_queue_tree_kind(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await adapter.create_queue_tree(
        mikrotik_creds,
        name="tree1",
        parent="ether1",
        packet_mark=None,
        max_limit_kbps=1000,
    )
    await adapter.remove_queue(mikrotik_creds, device_queue_id=device_id, queue_kind="tree")
    assert all(r[".id"] != device_id for r in api._menus[("queue", "tree")])


@pytest.mark.asyncio
async def test_read_queue_status_reads_real_counters(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            ("queue", "simple"): [
                {
                    ".id": "*1",
                    "name": "q1",
                    "target": "10.0.0.5/32",
                    "disabled": "false",
                    "bytes": "1000/2000",
                    "packets": "10/20",
                    "queued-bytes": "5/0",
                }
            ]
        }
    )
    patch_connect(api)
    adapter = MikroTikAdapter()

    status = await adapter.read_queue_status(mikrotik_creds, device_queue_id="*1")

    assert status == QueueDeviceStatus(
        device_queue_id="*1",
        name="q1",
        target="10.0.0.5/32",
        disabled=False,
        bytes_uploaded=1000,
        bytes_downloaded=2000,
        packets_uploaded=10,
        packets_downloaded=20,
        queued_bytes=5,
    )


@pytest.mark.asyncio
async def test_read_queue_status_missing_row_returns_empty_status(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)
    adapter = MikroTikAdapter()

    status = await adapter.read_queue_status(mikrotik_creds, device_queue_id="*999")

    assert status.name is None
    assert status.disabled is False


@pytest.mark.asyncio
async def test_queue_operation_failure_raises(patch_connect, mikrotik_creds):
    from librouteros.exceptions import LibRouterosError

    class ExplodingApi(FakeRouterOSApi):
        def path(self, *segments):
            path = super().path(*segments)

            def _raise(**kwargs):
                raise LibRouterosError("bad command")

            path.add = _raise
            return path

    api = ExplodingApi()
    patch_connect(api)
    adapter = MikroTikAdapter()
    with pytest.raises(MikroTikDeviceError):
        await adapter.create_simple_queue(
            mikrotik_creds,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
    assert api.closed is True


# ---------------------------------------------------------------------------
# The platform's row is the first row.
#
# RouterOS applies the first matching ``/queue simple`` in list order. A
# guest who signed in through RADIUS also has a dynamic ``<hotspot-...>``
# queue for the same address, and the hotspot puts those at the top -- so
# the row written here sat below it and matched nothing (observed live: the
# platform's row at 0 bytes under a dynamic row carrying the traffic).
#
# What these cannot show: whether a real RouterOS lets a static row be
# moved above a dynamic one. The fake's ``move`` does what it is told. The
# adapter therefore reads the list back and reports a row that is still
# shadowed, and that read-back is what is asserted for the refusing case.
# ---------------------------------------------------------------------------

_SIMPLE = ("queue", "simple")


def _dynamic_row(row_id: str, address: str) -> dict:
    return {
        ".id": row_id,
        "name": f"<hotspot-user-{row_id}>",
        "target": f"{address}/32",
        "max-limit": "40960000/40960000",
        "dynamic": "true",
    }


def _move(api, kwargs):
    rows = api._menus[_SIMPLE]
    moving = next(r for r in rows if r[".id"] == kwargs["numbers"])
    rows.remove(moving)
    at = next(i for i, r in enumerate(rows) if r[".id"] == kwargs["destination"])
    rows.insert(at, moving)
    return []


async def _create(adapter, creds, address="192.168.88.251"):
    return await adapter.create_simple_queue(
        creds,
        name="cloudguest-q",
        target=address,
        download_rate_kbps=20480,
        upload_rate_kbps=20480,
    )


@pytest.mark.asyncio
async def test_a_new_simple_queue_is_moved_above_the_rows_already_there(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_SIMPLE: [_dynamic_row("*7", "192.168.88.251"), _dynamic_row("*3", "192.168.88.252")]},
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    device_id = await _create(MikroTikAdapter(), mikrotik_creds)

    assert device_id == "*A"
    assert api.command_calls == [
        ("/queue/simple/move", {"numbers": "*A", "destination": "*7"})
    ]
    assert [r[".id"] for r in api._menus[_SIMPLE]] == ["*A", "*7", "*3"]
    assert api.closed is True


@pytest.mark.asyncio
async def test_a_row_that_is_already_first_is_not_moved(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(command_handlers={"/queue/simple/move": _move})
    patch_connect(api)

    await _create(MikroTikAdapter(), mikrotik_creds)

    assert api.command_calls == []


@pytest.mark.asyncio
async def test_an_updated_simple_queue_is_moved_back_to_the_top(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(command_handlers={"/queue/simple/move": _move})
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await _create(adapter, mikrotik_creds)
    # The guest signs in again: the hotspot puts a new dynamic row on top.
    api._menus[_SIMPLE].insert(0, _dynamic_row("*9", "192.168.88.251"))

    await adapter.update_simple_queue(
        mikrotik_creds,
        device_queue_id=device_id,
        download_rate_kbps=10240,
        upload_rate_kbps=10240,
    )

    assert [r[".id"] for r in api._menus[_SIMPLE]] == [device_id, "*9"]


@pytest.mark.asyncio
async def test_a_router_that_refuses_the_move_still_keeps_the_row_and_says_so(
    patch_connect, mikrotik_creds, caplog
):
    from librouteros.exceptions import LibRouterosError

    api = FakeRouterOSApi(
        menus={_SIMPLE: [_dynamic_row("*7", "192.168.88.251")]},
        raise_on_command={"/queue/simple/move": LibRouterosError("cannot move")},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    with caplog.at_level("WARNING"):
        device_id = await _create(MikroTikAdapter(), mikrotik_creds)

    assert device_id == "*A"
    assert [r[".id"] for r in api._menus[_SIMPLE]] == ["*7", "*A"]
    assert [r.msg for r in caplog.records] == ["simple_queue_raise_failed"]
    assert api.closed is True


@pytest.mark.asyncio
async def test_a_move_that_did_nothing_is_reported_as_shadowed_not_presumed_fixed(
    patch_connect, mikrotik_creds, caplog
):
    """RouterOS answering "done" to a move it did not perform is the case a
    fake that obeys cannot rule out, so the list is read back."""
    api = FakeRouterOSApi(
        menus={_SIMPLE: [_dynamic_row("*7", "192.168.88.251")]},
        command_handlers={"/queue/simple/move": lambda api, kwargs: []},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    with caplog.at_level("WARNING"):
        await _create(MikroTikAdapter(), mikrotik_creds)

    (record,) = caplog.records
    assert record.msg == "simple_queue_shadowed"
    assert record.shadowed_by == "<hotspot-user-*7>"
    assert record.shadowed_by_dynamic is True


@pytest.mark.asyncio
async def test_a_row_above_for_a_different_address_is_not_a_shadow(
    patch_connect, mikrotik_creds, caplog
):
    api = FakeRouterOSApi(
        menus={_SIMPLE: [_dynamic_row("*7", "192.168.88.9")]},
        command_handlers={"/queue/simple/move": lambda api, kwargs: []},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    with caplog.at_level("WARNING"):
        await _create(MikroTikAdapter(), mikrotik_creds)

    assert caplog.records == []


# ---------------------------------------------------------------------------
# find_client_address -- the router says what a device's address is.
# ---------------------------------------------------------------------------

_HOSTS = ("ip", "hotspot", "host")
_LEASES = ("ip", "dhcp-server", "lease")
_MAC = "9C:69:D3:00:00:17"


@pytest.mark.asyncio
async def test_find_client_address_prefers_the_hotspot_host(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            _HOSTS: [
                {".id": "*1", "mac-address": "AA:AA:AA:00:00:01", "address": "192.168.88.9"},
                {".id": "*2", "mac-address": _MAC, "address": "192.168.88.254", "to-address": "192.168.88.254", "bypassed": "true"},
            ],
            _LEASES: [{".id": "*1", "mac-address": _MAC, "address": "10.5.50.10", "status": "bound"}],
        }
    )
    patch_connect(api)

    found = await MikroTikAdapter().find_client_address(
        mikrotik_creds, mac_address=_MAC.lower().replace(":", "-")
    )

    assert found == "192.168.88.254"
    assert api.closed is True
    assert api.add_calls == api.update_calls == api.remove_calls == []


@pytest.mark.asyncio
async def test_find_client_address_is_the_devices_own_address_not_the_pool_one(
    patch_connect, mikrotik_creds
):
    """Clients leasing from a subnet that is not the hotspot's pool: the
    hotspot gives each a pool address (what ``$(ip)`` reports) for as long
    as it is translating them. The device's own address is the one that
    still describes it once it is bypassed."""
    api = FakeRouterOSApi(
        menus={_HOSTS: [{".id": "*1", "mac-address": _MAC, "address": "192.168.88.254", "to-address": "10.5.50.10"}]}
    )
    patch_connect(api)

    assert (
        await MikroTikAdapter().find_client_address(mikrotik_creds, mac_address=_MAC)
        == "192.168.88.254"
    )


@pytest.mark.asyncio
async def test_find_client_address_uses_to_address_when_it_is_all_the_host_has(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_HOSTS: [{".id": "*1", "mac-address": _MAC, "to-address": "10.5.50.77"}]}
    )
    patch_connect(api)

    assert (
        await MikroTikAdapter().find_client_address(mikrotik_creds, mac_address=_MAC)
        == "10.5.50.77"
    )


@pytest.mark.asyncio
async def test_find_client_address_falls_back_to_a_bound_lease(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={
            _LEASES: [
                {".id": "*1", "mac-address": _MAC, "address": "10.5.50.3", "status": "waiting"},
                {".id": "*2", "mac-address": _MAC, "address": "10.5.50.4", "status": "bound"},
                {".id": "*3", "mac-address": _MAC, "address": "10.5.50.5", "status": "bound", "disabled": "true"},
            ]
        }
    )
    patch_connect(api)

    assert (
        await MikroTikAdapter().find_client_address(mikrotik_creds, mac_address=_MAC)
        == "10.5.50.4"
    )


@pytest.mark.asyncio
async def test_find_client_address_without_a_hotspot_package_reads_the_lease(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_LEASES: [{".id": "*1", "mac-address": _MAC, "address": "10.5.50.4", "status": "bound"}]},
        missing_menus={_HOSTS},
    )
    patch_connect(api)

    assert (
        await MikroTikAdapter().find_client_address(mikrotik_creds, mac_address=_MAC)
        == "10.5.50.4"
    )


@pytest.mark.asyncio
async def test_find_client_address_is_none_for_a_device_the_router_has_not_seen(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_HOSTS: [{".id": "*1", "mac-address": "AA:AA:AA:00:00:01", "address": "192.168.88.9"}]}
    )
    patch_connect(api)
    adapter = MikroTikAdapter()

    assert await adapter.find_client_address(mikrotik_creds, mac_address=_MAC) is None
    assert await adapter.find_client_address(mikrotik_creds, mac_address="nonsense") is None


@pytest.mark.asyncio
async def test_find_client_address_falls_back_to_the_arp_table(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={
            ("ip", "arp"): [
                {".id": "*1", "mac-address": _MAC, "address": "10.5.50.8", "invalid": "true"},
                {".id": "*2", "mac-address": _MAC, "address": "10.5.50.9"},
            ]
        }
    )
    patch_connect(api)

    assert (
        await MikroTikAdapter().find_client_address(mikrotik_creds, mac_address=_MAC)
        == "10.5.50.9"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["192.168.88.0/24", "bridge", "10.5.50.7,10.5.50.0/24"])
async def test_a_venue_wide_row_is_not_raised_above_the_guests_own_rows(
    patch_connect, mikrotik_creds, target
):
    """A subnet or interface row matches every guest. First in the list, it
    would shadow each guest's own row."""
    api = FakeRouterOSApi(
        menus={_SIMPLE: [_dynamic_row("*7", "192.168.88.251")]},
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    await _create(MikroTikAdapter(), mikrotik_creds, address=target)

    assert api.command_calls == []
    assert [r[".id"] for r in api._menus[_SIMPLE]] == ["*7", "*A"]


@pytest.mark.asyncio
async def test_list_client_addresses_reads_each_table_once_and_prefers_the_host(
    patch_connect, mikrotik_creds
):
    other = "F2:A8:84:00:00:D7"
    arp_only = "AA:BB:CC:00:00:01"
    api = FakeRouterOSApi(
        menus={
            _HOSTS: [{".id": "*1", "mac-address": _MAC, "address": "10.5.50.253", "to-address": "10.5.50.253"}],
            _LEASES: [
                {".id": "*1", "mac-address": _MAC, "address": "10.5.50.254", "status": "waiting"},
                {".id": "*2", "mac-address": other, "address": "10.5.50.20", "status": "bound"},
            ],
            ("ip", "arp"): [
                {".id": "*1", "mac-address": other, "address": "10.5.50.99"},
                {".id": "*2", "mac-address": arp_only, "address": "10.5.50.30"},
            ],
        }
    )
    patch_connect(api)

    found = await MikroTikAdapter().list_client_addresses(mikrotik_creds)

    assert found == {_MAC: "10.5.50.253", other: "10.5.50.20", arp_only: "10.5.50.30"}
    assert api.closed is True
    assert api.add_calls == api.update_calls == api.remove_calls == []


@pytest.mark.asyncio
async def test_set_simple_queue_target_repoints_the_row_and_keeps_its_rates(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(command_handlers={"/queue/simple/move": _move})
    patch_connect(api)
    adapter = MikroTikAdapter()
    device_id = await _create(adapter, mikrotik_creds, address="10.5.50.254")
    api._menus[_SIMPLE].insert(0, _dynamic_row("*9", "10.5.50.253"))

    await adapter.set_simple_queue_target(
        mikrotik_creds, device_queue_id=device_id, target="10.5.50.253"
    )

    rows = api._menus[_SIMPLE]
    assert [r[".id"] for r in rows] == [device_id, "*9"]
    assert rows[0]["target"] == "10.5.50.253"
    assert rows[0]["max-limit"] == "20480k/20480k"
    assert api.update_calls[-1] == (_SIMPLE, {".id": device_id, "target": "10.5.50.253"})


# ---------------------------------------------------------------------------
# A venue's total speed cap: one parent row, the guests' rows under it.
#
# A packet enters the first top-level ``/queue simple`` row whose target it
# matches and, inside it, the first matching child. So the parent has to be
# the first row that can match a guest, the guests' rows have to name it as
# ``parent``, and a guest with no row of their own is still held by the
# parent because it targets the subnet.
#
# What these cannot show: that RouterOS accepts ``parent`` on ``add``/``set``
# over the API as written, or lets a static row be moved above a dynamic
# one. The fake does what it is told. Every write is therefore followed by a
# read of the list, and it is that read-back -- ``in_sync``/``problems`` --
# these assert for the refusing cases.
# ---------------------------------------------------------------------------

_VENUE = "cloudguest-venue-72425fa0"
_HOTSPOT = ("ip", "hotspot")
_ADDRESS = ("ip", "address")


def _guest_row(row_id: str, address: str, parent: str = "none") -> dict:
    return {
        ".id": row_id,
        "name": f"cloudguest-{row_id}",
        "target": f"{address}/32",
        "max-limit": "40960000/40960000",
        "parent": parent,
    }


def _venue_router(*simple_rows: dict, addresses: list[dict] | None = None) -> FakeRouterOSApi:
    api = FakeRouterOSApi(
        menus={
            _SIMPLE: list(simple_rows),
            _HOTSPOT: [{".id": "*1", "name": "hotspot1", "interface": "bridge"}],
            _ADDRESS: addresses
            if addresses is not None
            else [
                {".id": "*1", "address": "192.168.1.136/24", "interface": "ether1", "dynamic": "true"},
                {".id": "*2", "address": "192.168.88.1/24", "interface": "bridge"},
                {".id": "*3", "address": "10.20.0.46/24", "interface": "wg-cloudguard"},
            ],
        },
        command_handlers={"/queue/simple/move": _move},
    )
    counter = iter(f"*V{i}" for i in range(1, 50))
    api.mint_id = lambda row_count: next(counter)
    return api


async def _sync(adapter, creds, **overrides):
    kwargs = {
        "name": _VENUE,
        "download_rate_kbps": 81920,
        "upload_rate_kbps": 40960,
        "child_queue_ids": (),
        "comment": "venue cap",
    }
    kwargs.update(overrides)
    return await adapter.sync_venue_simple_queue(creds, **kwargs)


@pytest.mark.asyncio
async def test_a_venue_cap_becomes_one_parent_row_over_the_hotspots_own_subnet(
    patch_connect, mikrotik_creds
):
    api = _venue_router(_guest_row("*2", "192.168.88.254"), _guest_row("*4", "192.168.88.249"))
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds, child_queue_ids=("*2", "*4"))

    rows = api._menus[_SIMPLE]
    parent = rows[0]
    assert parent["name"] == _VENUE
    # The hotspot interface's network -- not the WAN's, not the tunnel's.
    assert parent["target"] == "192.168.88.0/24"
    assert parent["max-limit"] == "40960k/81920k"  # upload/download
    assert parent["comment"] == "venue cap"
    assert {r[".id"]: r["parent"] for r in rows[1:]} == {"*2": _VENUE, "*4": _VENUE}
    assert result.created and result.reparented == 2 and result.moved_to_top
    assert result.wrote and result.in_sync and result.problems == ()
    assert result.targets == ("192.168.88.0/24",)
    assert api.closed is True


@pytest.mark.asyncio
async def test_a_second_sync_reads_once_and_writes_nothing(patch_connect, mikrotik_creds):
    api = _venue_router(_guest_row("*2", "192.168.88.254"))
    patch_connect(api)
    adapter = MikroTikAdapter()
    await _sync(adapter, mikrotik_creds, child_queue_ids=("*2",))
    api.ops.clear()
    api.command_calls.clear()

    result = await _sync(adapter, mikrotik_creds, child_queue_ids=("*2",))

    assert api.ops == []
    assert api.command_calls == []
    assert result.wrote is False and result.in_sync is True
    assert not (result.created or result.updated or result.reparented)


@pytest.mark.asyncio
async def test_the_rate_routeros_prints_back_is_the_rate_that_was_sent(
    patch_connect, mikrotik_creds
):
    """RouterOS takes ``40960k`` and prints ``40960000``. Compared as text,
    every run would rewrite a row that is already right."""
    parent = {
        ".id": "*9",
        "name": _VENUE,
        "target": "192.168.88.0/24",
        "max-limit": "40960000/81920000",
        "parent": "none",
    }
    api = _venue_router(parent)
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds)

    assert api.ops == []
    assert result.wrote is False and result.in_sync is True


@pytest.mark.asyncio
async def test_a_changed_cap_is_one_update_of_the_existing_row(patch_connect, mikrotik_creds):
    api = _venue_router()
    patch_connect(api)
    adapter = MikroTikAdapter()
    first = await _sync(adapter, mikrotik_creds)
    api.ops.clear()

    result = await _sync(adapter, mikrotik_creds, download_rate_kbps=51200)

    assert [op[0] for op in api.ops] == ["update"]
    assert api._menus[_SIMPLE][0]["max-limit"] == "40960k/51200k"
    assert result.device_queue_id == first.device_queue_id
    assert result.updated and not result.created and result.in_sync


@pytest.mark.asyncio
async def test_one_direction_can_be_left_open(patch_connect, mikrotik_creds):
    api = _venue_router()
    patch_connect(api)

    await _sync(MikroTikAdapter(), mikrotik_creds, upload_rate_kbps=None)

    assert api._menus[_SIMPLE][0]["max-limit"] == "0k/81920k"


@pytest.mark.asyncio
async def test_a_router_set_up_over_its_defaults_gets_both_of_its_guest_networks(
    patch_connect, mikrotik_creds
):
    api = _venue_router(
        addresses=[
            {".id": "*1", "address": "192.168.88.1/24", "interface": "bridge"},
            {".id": "*2", "address": "10.5.50.1/24", "interface": "bridge"},
            {".id": "*3", "address": "203.0.113.9/24", "interface": "bridge"},
            {".id": "*4", "address": "172.16.9.1/24", "interface": "bridge", "disabled": "true"},
        ]
    )
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds)

    assert result.targets == ("10.5.50.0/24", "192.168.88.0/24")
    assert api._menus[_SIMPLE][0]["target"] == "10.5.50.0/24,192.168.88.0/24"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "menus",
    [
        {_HOTSPOT: []},
        {_HOTSPOT: [{".id": "*1", "interface": "bridge", "disabled": "true"}]},
        {_HOTSPOT: [{".id": "*1", "interface": "bridge"}], _ADDRESS: []},
        {
            _HOTSPOT: [{".id": "*1", "interface": "bridge"}],
            _ADDRESS: [{".id": "*1", "address": "203.0.113.9/24", "interface": "bridge"}],
        },
    ],
)
async def test_a_router_that_reports_no_guest_subnet_gets_nothing_written(
    patch_connect, mikrotik_creds, menus
):
    api = FakeRouterOSApi(menus={_SIMPLE: [_guest_row("*2", "192.168.88.254")], **menus})
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds, child_queue_ids=("*2",))

    assert api.ops == []
    assert api._menus[_SIMPLE] == [_guest_row("*2", "192.168.88.254")]
    assert result.in_sync is False
    assert result.problems == ("guest_subnet_unresolved",)
    assert result.device_queue_id is None


@pytest.mark.asyncio
async def test_a_router_without_the_hotspot_package_gets_nothing_written(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(missing_menus={_HOTSPOT})
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds)

    assert api.ops == []
    assert result.problems == ("guest_subnet_unresolved",)


@pytest.mark.asyncio
async def test_a_dynamic_row_left_above_the_parent_is_reported_not_presumed_gone(
    patch_connect, mikrotik_creds, caplog
):
    """The move is accepted and does nothing -- the case a real RouterOS may
    turn out to be for a static row and a dynamic one."""
    api = _venue_router(_dynamic_row("*7", "192.168.88.251"))
    api._command_handlers["/queue/simple/move"] = lambda api, kwargs: []
    patch_connect(api)

    with caplog.at_level("WARNING"):
        result = await _sync(MikroTikAdapter(), mikrotik_creds)

    assert [r[".id"] for r in api._menus[_SIMPLE]][0] == "*7"
    assert result.in_sync is False
    assert "top_level_row_above_parent" in result.problems
    (record,) = [r for r in caplog.records if r.msg == "venue_simple_queue_not_in_sync"]
    assert record.problems == ["top_level_row_above_parent"]


@pytest.mark.asyncio
async def test_a_router_that_refuses_the_move_still_keeps_the_parent_and_its_children(
    patch_connect, mikrotik_creds, caplog
):
    """A refused reorder is not a failed venue cap: the parent is on the
    device with the guests' rows under it, and the result says it is not
    first."""
    from librouteros.exceptions import LibRouterosError

    api = _venue_router(_dynamic_row("*7", "192.168.88.251"), _guest_row("*2", "192.168.88.254"))
    api._raise_on_command["/queue/simple/move"] = LibRouterosError("cannot move before dynamic")
    patch_connect(api)

    with caplog.at_level("WARNING"):
        result = await _sync(MikroTikAdapter(), mikrotik_creds, child_queue_ids=("*2",))

    rows = {r[".id"]: r for r in api._menus[_SIMPLE]}
    assert result.device_queue_id in rows
    assert rows["*2"]["parent"] == _VENUE
    assert result.created and result.reparented == 1 and not result.moved_to_top
    assert result.in_sync is False
    assert "top_level_row_above_parent" in result.problems
    assert any(r.msg == "venue_simple_queue_move_refused" for r in caplog.records)
    assert api.closed is True


@pytest.mark.asyncio
async def test_a_child_the_router_did_not_put_under_the_parent_is_reported(
    patch_connect, mikrotik_creds
):
    api = _venue_router(_guest_row("*2", "192.168.88.254"))
    api.silently_ignore_updates.add(_SIMPLE)
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds, child_queue_ids=("*2",))

    assert result.in_sync is False
    assert "child_not_under_parent" in result.problems


@pytest.mark.asyncio
async def test_a_child_id_the_router_no_longer_holds_is_not_an_error(
    patch_connect, mikrotik_creds
):
    api = _venue_router()
    patch_connect(api)

    result = await _sync(MikroTikAdapter(), mikrotik_creds, child_queue_ids=("*gone",))

    assert result.in_sync is True and result.reparented == 0


@pytest.mark.asyncio
async def test_a_guest_row_created_under_a_parent_names_it_and_is_not_raised_above_it(
    patch_connect, mikrotik_creds
):
    api = _venue_router()
    patch_connect(api)
    adapter = MikroTikAdapter()
    parent = await _sync(adapter, mikrotik_creds)
    api.command_calls.clear()

    child_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="cloudguest-q",
        target="192.168.88.254",
        download_rate_kbps=40960,
        upload_rate_kbps=40960,
        parent=_VENUE,
    )

    (_, fields) = api.add_calls[-1]
    assert fields["parent"] == _VENUE
    # The parent was already first, so nothing is moved -- least of all the
    # child above it.
    assert api.command_calls == []
    assert [r[".id"] for r in api._menus[_SIMPLE]] == [parent.device_queue_id, child_id]


@pytest.mark.asyncio
async def test_a_child_write_puts_its_parent_back_on_top_of_a_dynamic_row(
    patch_connect, mikrotik_creds
):
    """A RADIUS sign-in adds a dynamic row at the top, above the parent. The
    next write of a guest's row moves the parent -- not the guest's row --
    back to the top."""
    api = _venue_router()
    patch_connect(api)
    adapter = MikroTikAdapter()
    parent = await _sync(adapter, mikrotik_creds)
    api._menus[_SIMPLE].insert(0, _dynamic_row("*7", "192.168.88.251"))
    api.command_calls.clear()

    child_id = await adapter.create_simple_queue(
        mikrotik_creds,
        name="cloudguest-q",
        target="192.168.88.254",
        download_rate_kbps=40960,
        upload_rate_kbps=40960,
        parent=_VENUE,
    )

    assert api.command_calls == [
        ("/queue/simple/move", {"numbers": parent.device_queue_id, "destination": "*7"})
    ]
    assert [r[".id"] for r in api._menus[_SIMPLE]] == [parent.device_queue_id, "*7", child_id]


@pytest.mark.asyncio
async def test_a_guest_row_without_a_parent_carries_no_parent_field(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi()
    patch_connect(api)

    await _create(MikroTikAdapter(), mikrotik_creds)

    (_, fields) = api.add_calls[-1]
    assert "parent" not in fields


@pytest.mark.asyncio
async def test_clearing_returns_the_guests_rows_to_the_top_level_then_removes_the_parent(
    patch_connect, mikrotik_creds
):
    api = _venue_router(_guest_row("*2", "192.168.88.254"), _guest_row("*4", "192.168.88.249"))
    patch_connect(api)
    adapter = MikroTikAdapter()
    await _sync(adapter, mikrotik_creds, child_queue_ids=("*2", "*4"))
    api.ops.clear()

    result = await adapter.clear_venue_simple_queue(mikrotik_creds, name=_VENUE)

    assert [op[0] for op in api.ops] == ["update", "update", "remove"]
    assert {r[".id"]: r["parent"] for r in api._menus[_SIMPLE]} == {"*2": "none", "*4": "none"}
    assert result.removed and result.reparented == 2 and result.in_sync
    assert api.closed is True


@pytest.mark.asyncio
async def test_a_parent_whose_rows_would_not_leave_it_is_left_in_place(
    patch_connect, mikrotik_creds
):
    api = _venue_router(_guest_row("*2", "192.168.88.254"))
    patch_connect(api)
    adapter = MikroTikAdapter()
    await _sync(adapter, mikrotik_creds, child_queue_ids=("*2",))
    api.silently_ignore_updates.add(_SIMPLE)
    api.ops.clear()

    result = await adapter.clear_venue_simple_queue(mikrotik_creds, name=_VENUE)

    assert "remove" not in [op[0] for op in api.ops]
    assert any(r["name"] == _VENUE for r in api._menus[_SIMPLE])
    assert result.removed is False and result.in_sync is False
    assert set(result.problems) == {"parent_still_present", "rows_still_under_parent"}


@pytest.mark.asyncio
async def test_clearing_a_cap_that_is_not_there_writes_nothing(patch_connect, mikrotik_creds):
    api = _venue_router(_guest_row("*2", "192.168.88.254"))
    patch_connect(api)

    result = await MikroTikAdapter().clear_venue_simple_queue(mikrotik_creds, name=_VENUE)

    assert api.ops == []
    assert result.wrote is False and result.in_sync is True and result.removed is False


@pytest.mark.asyncio
async def test_a_venue_cap_write_the_router_refuses_raises(patch_connect, mikrotik_creds):
    """A RouterOS that will not take the row says so through the adapter's
    own error, with the connection closed -- not through a result that
    reads as written."""
    from librouteros.exceptions import LibRouterosError

    api = _venue_router()
    plain_path = api.path

    def _path(*segments):
        found = plain_path(*segments)
        if segments == _SIMPLE:

            def _add(**fields):
                raise LibRouterosError("input does not match any value of parent")

            found.add = _add
        return found

    api.path = _path
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await _sync(MikroTikAdapter(), mikrotik_creds)
    assert api._menus[_SIMPLE] == []
    assert api.closed is True


# ---------------------------------------------------------------------------
# A guest's new row is the only row of its kind for that address.
#
# A changed limit is a new row, and the row it replaces is removed by the
# caller in a second call. "No limit" is a row too (``max-limit=0/0``). When
# that second call fails -- or its record is rolled back -- both stay, and
# RouterOS takes the first that matches: limit -> no limit -> limit left a
# guest unlimited under a limit the venue had just set. Moving the new row
# to the top hides it only where the move works, so the write that adds the
# row also takes the others away.
# ---------------------------------------------------------------------------

_GUEST = "192.168.88.251"
_PREFIX = "cloudguest-"
_OLD_ROW = "cloudguest-11111111-1111-4111-8111-111111111111"
_NEW_ROW = "cloudguest-22222222-2222-4222-8222-222222222222"


def _static_row(row_id: str, name: str, target: str, limit: str = "0/0", **more) -> dict:
    return {".id": row_id, "name": name, "target": target, "max-limit": limit, **more}


def _governing(api, address: str) -> dict | None:
    """The first row whose target is this address: what RouterOS applies."""
    for row in api._menus[_SIMPLE]:
        if address in {t.strip().removesuffix("/32") for t in row["target"].split(",")}:
            return row
    return None


async def _create_guest_row(adapter, creds, **kwargs):
    return await adapter.create_simple_queue(
        creds,
        name=_NEW_ROW,
        target=_GUEST,
        download_rate_kbps=81920,
        upload_rate_kbps=81920,
        supersede_name_prefix=_PREFIX,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_an_unlimited_row_left_above_does_not_outlive_the_new_limit(
    patch_connect, mikrotik_creds
):
    """Limit -> no limit -> limit, on a router that will not reorder rows:
    the ``0/0`` row is first, the new one is added below it."""
    from librouteros.exceptions import LibRouterosError

    api = FakeRouterOSApi(
        menus={_SIMPLE: [_static_row("*5", _OLD_ROW, f"{_GUEST}/32")]},
        raise_on_command={"/queue/simple/move": LibRouterosError("cannot move")},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    device_id = await _create_guest_row(MikroTikAdapter(), mikrotik_creds)

    assert [r[".id"] for r in api._menus[_SIMPLE]] == [device_id]
    assert _governing(api, _GUEST)["max-limit"] == "81920k/81920k"
    # Added first, removed second: never a moment with no row.
    writes = [op[0] for op in api.ops if op[0] in ("add", "remove")]
    assert writes == ["add", "remove"]
    assert api.remove_calls == [(_SIMPLE, ("*5",))]


@pytest.mark.asyncio
async def test_only_this_addresss_own_guest_rows_are_taken_away(
    patch_connect, mikrotik_creds
):
    untouched = [
        _dynamic_row("*7", _GUEST),
        _static_row("*8", "cloudguest-33333333-3333-4333-8333-333333333333", "192.168.88.9"),
        _static_row("*9", "cloudguest-venue-0a1b2c3d", "192.168.88.0/24", "0/81920000"),
        _static_row("*10", "cloudguest-qos-44444444-4444-4444-8444-444444444444", _GUEST),
        _static_row("*11", "front-desk", f"{_GUEST}/32"),
        _static_row("*12", "cloudguest-55555555-5555-4555-8555-555555555555", _GUEST),
        _static_row(
            "*13",
            "cloudguest-66666666-6666-4666-8666-666666666666",
            f"{_GUEST}/32,192.168.88.9/32",
        ),
    ]
    api = FakeRouterOSApi(
        menus={_SIMPLE: [*untouched, _static_row("*5", _OLD_ROW, f"{_GUEST}/32")]},
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    await _create_guest_row(MikroTikAdapter(), mikrotik_creds, keep_queue_ids=("*12",))

    assert api.remove_calls == [(_SIMPLE, ("*5",))]
    assert [r[".id"] for r in api._menus[_SIMPLE]] == [
        "*A",
        *[r[".id"] for r in untouched],
    ]


@pytest.mark.asyncio
async def test_a_row_created_without_the_prefix_removes_nothing(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_SIMPLE: [_static_row("*5", _OLD_ROW, f"{_GUEST}/32")]},
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    await _create(MikroTikAdapter(), mikrotik_creds, address=_GUEST)

    assert api.remove_calls == []
    assert [r[".id"] for r in api._menus[_SIMPLE]] == ["*A", "*5"]


@pytest.mark.asyncio
async def test_writing_the_same_guest_row_again_finds_nothing_to_remove(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(command_handlers={"/queue/simple/move": _move})
    patch_connect(api)

    await _create_guest_row(MikroTikAdapter(), mikrotik_creds)

    assert api.remove_calls == []
    assert len(api._menus[_SIMPLE]) == 1


@pytest.mark.asyncio
async def test_an_old_row_the_router_will_not_remove_fails_the_write_and_undoes_it(
    patch_connect, mikrotik_creds, monkeypatch
):
    """The row that could not be taken away may be the one that governs, so
    the caller is not told the new limit is in place -- and is not left
    with a row it holds no id for."""
    from librouteros.exceptions import LibRouterosError

    from tests.fake_write_transport import FakePath

    api = FakeRouterOSApi(
        menus={_SIMPLE: [_static_row("*5", _OLD_ROW, f"{_GUEST}/32")]},
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)
    plain_remove = FakePath.remove

    def _remove(self, *ids):
        if ids == ("*5",):
            raise LibRouterosError("failure: busy")
        plain_remove(self, *ids)

    monkeypatch.setattr(FakePath, "remove", _remove)

    with pytest.raises(MikroTikDeviceError):
        await _create_guest_row(MikroTikAdapter(), mikrotik_creds)

    assert [r[".id"] for r in api._menus[_SIMPLE]] == ["*5"]
    assert api.closed is True


@pytest.mark.asyncio
async def test_an_old_row_that_has_already_gone_is_not_a_failure(
    patch_connect, mikrotik_creds, monkeypatch
):
    from librouteros.exceptions import LibRouterosError

    from tests.fake_write_transport import FakePath

    api = FakeRouterOSApi(
        menus={_SIMPLE: [_static_row("*5", _OLD_ROW, f"{_GUEST}/32")]},
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    def _remove(self, *ids):
        self._rows[:] = [row for row in self._rows if row.get(".id") not in ids]
        raise LibRouterosError("no such item")

    monkeypatch.setattr(FakePath, "remove", _remove)

    device_id = await _create_guest_row(MikroTikAdapter(), mikrotik_creds)

    assert [r[".id"] for r in api._menus[_SIMPLE]] == [device_id]


@pytest.mark.asyncio
async def test_a_guest_row_under_a_venue_parent_replaces_its_sibling_not_the_parent(
    patch_connect, mikrotik_creds
):
    parent = _static_row("*P", "cloudguest-venue-0a1b2c3d", "192.168.88.0/24", "0/163840000")
    api = FakeRouterOSApi(
        menus={
            _SIMPLE: [
                parent,
                _static_row("*5", _OLD_ROW, f"{_GUEST}/32", parent="cloudguest-venue-0a1b2c3d"),
            ]
        },
        command_handlers={"/queue/simple/move": _move},
    )
    api.mint_id = lambda row_count: "*A"
    patch_connect(api)

    await _create_guest_row(
        MikroTikAdapter(), mikrotik_creds, parent="cloudguest-venue-0a1b2c3d"
    )

    assert [r[".id"] for r in api._menus[_SIMPLE]] == ["*P", "*A"]
    assert api.command_calls == []

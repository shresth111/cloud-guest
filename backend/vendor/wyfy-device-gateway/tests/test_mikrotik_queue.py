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
async def test_find_client_address_uses_the_translated_address_when_they_differ(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_HOSTS: [{".id": "*1", "mac-address": _MAC, "address": "192.168.1.50", "to-address": "10.5.50.77"}]}
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

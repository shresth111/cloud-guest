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

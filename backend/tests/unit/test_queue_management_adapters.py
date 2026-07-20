"""Unit tests for the Queue Management Engine's real device I/O adapter
layer (``app.domains.queue_management.device_adapters``).

Per that module's own "real client code, untested end-to-end here" scope
note, ``MikroTikQueueAdapter``'s command-construction and response-parsing
logic is exercised here via a hand-rolled fake ``librouteros`` transport
(monkeypatching ``librouteros.connect``) that faithfully mirrors the real
library's own ``Path.add``/``.update``/``.remove``/iteration contract --
never a real socket. This mirrors
``tests/unit/test_provisioning_engine_adapters.py``'s own identical
discipline. Also covers a genuine, real-network negative case: a
connection attempt to a guaranteed-unreachable TEST-NET-1 address
(``192.0.2.1``), bounded by a 1-second timeout, which must raise a real
``QueueDeviceConnectionError``, never a fabricated success.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import itertools

import librouteros
import pytest
from librouteros.exceptions import LibRouterosError

from app.domains.queue_management.device_adapters import (
    MikroTikQueueAdapter,
    QueueCredentials,
    get_queue_adapter,
    list_supported_queue_vendors,
)
from app.domains.queue_management.exceptions import (
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
    UnsupportedQueueVendorError,
)

CREDENTIALS = QueueCredentials(host="10.0.0.1", username="admin", password="secret")


# ============================================================================
# Registry
# ============================================================================


class TestQueueAdapterRegistry:
    def test_mikrotik_is_registered(self) -> None:
        adapter = get_queue_adapter("mikrotik")
        assert isinstance(adapter, MikroTikQueueAdapter)
        assert adapter.vendor == "mikrotik"

    def test_unknown_vendor_raises(self) -> None:
        with pytest.raises(UnsupportedQueueVendorError):
            get_queue_adapter("opnsense")

    def test_list_supported_queue_vendors(self) -> None:
        assert list_supported_queue_vendors() == ["mikrotik"]


# ============================================================================
# Fake librouteros transport -- mirrors the real library's own
# Path.add/.update/.remove/iteration contract (confirmed against
# site-packages/librouteros/api.py -- see device_adapters.py's own module
# docstring).
# ============================================================================


class FakePath:
    def __init__(self, store: dict[str, dict], id_counter: itertools.count) -> None:
        self.store = store
        self._id_counter = id_counter

    def add(self, **kwargs: object) -> str:
        new_id = f"*{next(self._id_counter)}"
        self.store[new_id] = {".id": new_id, **kwargs}
        return new_id

    def update(self, **kwargs: object) -> None:
        fields = dict(kwargs)
        row_id = fields.pop(".id")
        self.store.setdefault(row_id, {".id": row_id}).update(fields)

    def remove(self, *ids: str) -> None:
        for row_id in ids:
            self.store.pop(row_id, None)

    def __iter__(self):
        return iter(list(self.store.values()))


class FakeRouterosApi:
    def __init__(self) -> None:
        self._paths: dict[tuple[str, ...], dict[str, dict]] = {}
        self._id_counter = itertools.count(1)
        self.closed = False

    def path(self, *segments: str) -> FakePath:
        store = self._paths.setdefault(segments, {})
        return FakePath(store, self._id_counter)

    def close(self) -> None:
        self.closed = True


class RaisingConnect:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def __call__(self, *args: object, **kwargs: object) -> None:
        raise self.exc


# ============================================================================
# create_simple_queue / update_simple_queue / delete_simple_queue
# ============================================================================


class TestSimpleQueue:
    async def test_create_formats_rates_and_burst_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()

        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
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

        row = api._paths[("queue", "simple")][device_id]
        assert row["name"] == "cloudguest-q1"
        assert row["target"] == "10.0.0.5/32"
        assert row["max-limit"] == "1000k/5000k"
        assert row["burst-limit"] == "2000k/8000k"
        assert row["burst-threshold"] == "4000k/4000k"
        assert row["burst-time"] == "8/8"
        assert row["priority"] == "3"
        assert api.closed is True

    async def test_create_without_burst_omits_burst_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()

        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
            name="q2",
            target="10.0.0.6/32",
            download_rate_kbps=2000,
            upload_rate_kbps=512,
        )
        row = api._paths[("queue", "simple")][device_id]
        assert "burst-limit" not in row
        assert "burst-threshold" not in row
        assert "burst-time" not in row

    async def test_update_changes_existing_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )

        await adapter.update_simple_queue(
            CREDENTIALS,
            device_queue_id=device_id,
            download_rate_kbps=9000,
            upload_rate_kbps=3000,
            priority=1,
        )
        row = api._paths[("queue", "simple")][device_id]
        assert row["max-limit"] == "3000k/9000k"
        assert row["priority"] == "1"

    async def test_delete_removes_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        await adapter.delete_simple_queue(CREDENTIALS, device_queue_id=device_id)
        assert device_id not in api._paths[("queue", "simple")]

    async def test_connection_failure_raises_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            librouteros, "connect", RaisingConnect(OSError("connection refused"))
        )
        adapter = MikroTikQueueAdapter()
        with pytest.raises(QueueDeviceConnectionError):
            await adapter.create_simple_queue(
                CREDENTIALS,
                name="q1",
                target="10.0.0.5/32",
                download_rate_kbps=1000,
                upload_rate_kbps=500,
            )


# ============================================================================
# create_queue_tree / apply_pcq
# ============================================================================


class TestQueueTreeAndPcq:
    async def test_create_queue_tree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()

        device_id = await adapter.create_queue_tree(
            CREDENTIALS,
            name="org-ceiling",
            parent="ether1",
            packet_mark="org-mark",
            max_limit_kbps=100000,
            priority=4,
            queue_type_name="fair-share",
        )
        row = api._paths[("queue", "tree")][device_id]
        assert row["parent"] == "ether1"
        assert row["packet-mark"] == "org-mark"
        assert row["max-limit"] == "100000k"
        assert row["priority"] == "4"
        assert row["queue"] == "fair-share"

    async def test_apply_pcq(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()

        device_id = await adapter.apply_pcq(
            CREDENTIALS, name="fair-share", rate_kbps=50000, classifier="src-address"
        )
        row = api._paths[("queue", "type")][device_id]
        assert row["kind"] == "pcq"
        assert row["pcq-rate"] == "50000k"
        assert row["pcq-classifier"] == "src-address"


# ============================================================================
# set_priority / assign_queue_to_target / remove_queue
# ============================================================================


class TestPriorityTargetAndRemove:
    async def test_set_priority(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        await adapter.set_priority(CREDENTIALS, device_queue_id=device_id, priority=2)
        assert api._paths[("queue", "simple")][device_id]["priority"] == "2"

    async def test_assign_queue_to_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        await adapter.assign_queue_to_target(
            CREDENTIALS, device_queue_id=device_id, target="10.0.0.99/32"
        )
        assert api._paths[("queue", "simple")][device_id]["target"] == "10.0.0.99/32"

    async def test_remove_queue_tree_kind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        device_id = await adapter.create_queue_tree(
            CREDENTIALS,
            name="tree1",
            parent="ether1",
            packet_mark=None,
            max_limit_kbps=1000,
        )
        await adapter.remove_queue(
            CREDENTIALS, device_queue_id=device_id, queue_kind="tree"
        )
        assert device_id not in api._paths[("queue", "tree")]


# ============================================================================
# read_queue_status
# ============================================================================


class TestReadQueueStatus:
    async def test_reads_real_counters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        device_id = await adapter.create_simple_queue(
            CREDENTIALS,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=500,
        )
        api._paths[("queue", "simple")][device_id].update(
            {
                "disabled": "false",
                "bytes": "1000/2000",
                "packets": "10/20",
                "queued-bytes": "5/0",
            }
        )

        status = await adapter.read_queue_status(CREDENTIALS, device_queue_id=device_id)
        assert status.name == "q1"
        assert status.target == "10.0.0.5/32"
        assert status.disabled is False
        assert status.bytes_uploaded == 1000
        assert status.bytes_downloaded == 2000
        assert status.packets_uploaded == 10
        assert status.packets_downloaded == 20
        assert status.queued_bytes == 5

    async def test_missing_row_returns_empty_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        status = await adapter.read_queue_status(CREDENTIALS, device_queue_id="*999")
        assert status.name is None
        assert status.disabled is False


class TestOperationFailure:
    async def test_command_failure_raises_operation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class ExplodingPath(FakePath):
            def add(self, **kwargs: object) -> str:
                raise LibRouterosError("bad command")

        class ExplodingApi(FakeRouterosApi):
            def path(self, *segments: str) -> FakePath:
                store = self._paths.setdefault(segments, {})
                return ExplodingPath(store, self._id_counter)

        api = ExplodingApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQueueAdapter()
        with pytest.raises(QueueDeviceOperationError):
            await adapter.create_simple_queue(
                CREDENTIALS,
                name="q1",
                target="10.0.0.5/32",
                download_rate_kbps=1000,
                upload_rate_kbps=500,
            )
        assert api.closed is True


# ============================================================================
# Real, bounded, guaranteed-unreachable-host negative case
# ============================================================================


class TestRealUnreachableHostNeverFabricatesSuccess:
    async def test_connecting_to_test_net_1_raises_honest_connection_error(
        self,
    ) -> None:
        """``192.0.2.1`` is a TEST-NET-1 address (RFC 5737) -- reserved for
        documentation/testing, guaranteed never to route anywhere. A real
        connection attempt against it, with a short timeout, must raise a
        real ``QueueDeviceConnectionError`` -- never a fabricated success.
        This is the one test in this file that opens a real (and
        always-failing) socket."""
        adapter = MikroTikQueueAdapter()
        credentials = QueueCredentials(
            host="192.0.2.1", username="admin", password="secret", timeout_seconds=1
        )
        with pytest.raises(QueueDeviceConnectionError):
            await adapter.create_simple_queue(
                credentials,
                name="q1",
                target="10.0.0.5/32",
                download_rate_kbps=1000,
                upload_rate_kbps=500,
            )

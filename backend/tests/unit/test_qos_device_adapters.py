"""Unit tests for the QoS & VOIP Priority domain's real device I/O adapter
layer (``app.domains.qos.device_adapters``).

Mirrors ``tests/unit/test_queue_management_adapters.py``'s own structure
and rationale exactly: ``MikroTikQosQueueAdapter`` delegates every
operation to ``wyfy_device_gateway.registry.get_adapter(DeviceVendor
.MIKROTIK)`` -- the real RouterOS command-construction/response-parsing
logic itself lives in, and is exhaustively unit-tested by,
``wyfy-device-gateway``'s own test suite against a fake transport there.
What this file verifies is the delegation chain end-to-end: credential
translation (``QosCredentials`` -> ``wyfy_device_gateway.contract
.DeviceCredentials``), the real ``/queue tree`` command shape this domain
requests (fixed ``parent``/``max-limit``, per-rule ``packet-mark``/
``priority``), and error translation (``MikroTikConnectionError``/
``MikroTikDeviceError`` -> this domain's own ``QosDeviceConnectionError``/
``QosDeviceOperationError``). Also covers a genuine, real-network negative
case identical in spirit to the queue_management original: a connection
attempt to a guaranteed-unreachable TEST-NET-1 address, bounded by a
1-second timeout, which must raise a real ``QosDeviceConnectionError``,
never a fabricated success.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import itertools

import librouteros
import pytest
from librouteros.exceptions import LibRouterosError

from app.domains.qos.constants import (
    QOS_QUEUE_TREE_PARENT,
    QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS,
)
from app.domains.qos.device_adapters import (
    MikroTikQosQueueAdapter,
    QosCredentials,
    get_qos_queue_adapter,
    list_supported_qos_vendors,
)
from app.domains.qos.exceptions import (
    QosDeviceConnectionError,
    QosDeviceOperationError,
    UnsupportedQosVendorError,
)

CREDENTIALS = QosCredentials(host="10.0.0.1", username="admin", password="secret")


# ============================================================================
# Registry
# ============================================================================


class TestQosQueueAdapterRegistry:
    def test_mikrotik_is_registered(self) -> None:
        adapter = get_qos_queue_adapter("mikrotik")
        assert isinstance(adapter, MikroTikQosQueueAdapter)
        assert adapter.vendor == "mikrotik"

    def test_unknown_vendor_raises(self) -> None:
        with pytest.raises(UnsupportedQosVendorError):
            get_qos_queue_adapter("opnsense")

    def test_list_supported_qos_vendors(self) -> None:
        assert list_supported_qos_vendors() == ["mikrotik"]


# ============================================================================
# Fake librouteros transport -- identical shape to
# test_queue_management_adapters.py's own (mirrors the real library's own
# Path.add/.update/.remove/iteration contract).
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
# create_priority_queue
# ============================================================================


class TestCreatePriorityQueue:
    async def test_creates_a_real_queue_tree_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQosQueueAdapter()

        device_id = await adapter.create_priority_queue(
            CREDENTIALS,
            name="cloudguest-qos-abc123",
            packet_mark="sip-signaling-abc123",
            priority=1,
        )

        row = api._paths[("queue", "tree")][device_id]
        assert row["name"] == "cloudguest-qos-abc123"
        # The fixed, domain-wide parent/max-limit -- see constants.py's own
        # docstrings for why neither is derived per-rule.
        assert row["parent"] == QOS_QUEUE_TREE_PARENT
        assert row["max-limit"] == f"{QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS}k"
        assert row["packet-mark"] == "sip-signaling-abc123"
        assert row["priority"] == "1"
        assert "queue" not in row  # no PCQ queue-type name for this domain
        assert api.closed is True

    async def test_connection_failure_raises_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            librouteros, "connect", RaisingConnect(OSError("connection refused"))
        )
        adapter = MikroTikQosQueueAdapter()
        with pytest.raises(QosDeviceConnectionError):
            await adapter.create_priority_queue(
                CREDENTIALS, name="q1", packet_mark="mark1", priority=1
            )

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
        adapter = MikroTikQosQueueAdapter()
        with pytest.raises(QosDeviceOperationError):
            await adapter.create_priority_queue(
                CREDENTIALS, name="q1", packet_mark="mark1", priority=1
            )
        assert api.closed is True


# ============================================================================
# set_priority / remove_priority_queue
# ============================================================================


class TestSetPriorityAndRemove:
    async def test_set_priority_updates_the_tree_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQosQueueAdapter()
        device_id = await adapter.create_priority_queue(
            CREDENTIALS, name="q1", packet_mark="mark1", priority=8
        )

        await adapter.set_priority(CREDENTIALS, device_queue_id=device_id, priority=1)

        row = api._paths[("queue", "tree")][device_id]
        assert row["priority"] == "1"
        # set_priority must never touch the packet-mark/parent/name fields.
        assert row["packet-mark"] == "mark1"

    async def test_remove_priority_queue_removes_the_tree_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikQosQueueAdapter()
        device_id = await adapter.create_priority_queue(
            CREDENTIALS, name="q1", packet_mark="mark1", priority=1
        )

        await adapter.remove_priority_queue(CREDENTIALS, device_queue_id=device_id)

        assert device_id not in api._paths[("queue", "tree")]

    async def test_set_priority_connection_failure_raises_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            librouteros, "connect", RaisingConnect(OSError("connection refused"))
        )
        adapter = MikroTikQosQueueAdapter()
        with pytest.raises(QosDeviceConnectionError):
            await adapter.set_priority(CREDENTIALS, device_queue_id="*1", priority=1)


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
        real ``QosDeviceConnectionError`` -- never a fabricated success.
        Identical rationale to ``test_queue_management_adapters.py``'s own
        equivalent test."""
        adapter = MikroTikQosQueueAdapter()
        credentials = QosCredentials(
            host="192.0.2.1", username="admin", password="secret", timeout_seconds=1
        )
        with pytest.raises(QosDeviceConnectionError):
            await adapter.create_priority_queue(
                credentials, name="q1", packet_mark="mark1", priority=1
            )

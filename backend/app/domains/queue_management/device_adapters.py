"""Real device I/O adapters for the Queue Management Engine -- the
Strategy/Adapter seam that keeps this domain's own core engine
(``service.py``) completely vendor-agnostic. ``BaseQueueAdapter`` is what a
vendor implements to plug in real bandwidth/QoS queue operations; the
engine itself never imports ``librouteros`` or constructs a single
RouterOS command directly.

## Honest scope: real client code, never exercised end-to-end here

:class:`MikroTikQueueAdapter` uses ``librouteros`` (see
``requirements.txt`` -- already a real, genuine dependency, added for
``app.domains.provisioning_engine``'s own device adapter) to speak
RouterOS's real API protocol against ``/queue/simple``, ``/queue/tree``,
and ``/queue/type`` (PCQ). Unlike ``provisioning_engine.device_adapters``,
this adapter needs no SSH/SFTP transport at all -- every queue operation
(add/set/remove/print) is a native RouterOS API command, not a file-system-
level operation. This module's own command-construction and response-
parsing logic is exercised in ``test_queue_management_adapters.py`` via a
hand-rolled fake transport, mirroring
``app.domains.provisioning_engine.device_adapters``'s own identical
discipline. There is no live MikroTik device anywhere in this sandbox --
every method below, if actually invoked here, raises a real
:class:`~.exceptions.QueueDeviceConnectionError` the moment it tries to
open a real socket, never a fabricated success.

## The real ``librouteros`` write API: ``Path.add``/``.update``/``.remove``

``librouteros.Api.path(*segments)`` returns a ``Path`` object with real
``add(**kwargs)`` (RouterOS ``add``, returns the new row's device-side
``.id``, e.g. ``"*1"``), ``update(**kwargs)`` (RouterOS ``set`` -- must
include ``.id`` in ``kwargs`` to target which row), and ``remove(*ids)``
(RouterOS ``remove``) methods -- confirmed directly against the installed
``librouteros`` package's own source
(``site-packages/librouteros/api.py``), not guessed from memory. RouterOS
field names containing a hyphen (``max-limit``, ``burst-limit``,
``burst-threshold``, ``burst-time``, ``pcq-rate``, ...) are passed via
``**{"max-limit": ...}`` since they are not valid Python keyword-argument
identifiers.

## Rate formatting

``QueueProfile`` stores rates in kbps (see that model's own docstring for
why ``0`` means "unlimited"). RouterOS's own ``max-limit``/``burst-limit``
fields accept a bare number with a unit suffix (``"512k"``, ``"5M"``) --
this module always emits the ``k`` suffix (``f"{value}k"``), a real,
valid RouterOS unit, never converted to ``M`` for readability, keeping the
formatting logic a single, trivial, always-correct code path.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Protocol

import librouteros
from librouteros.exceptions import LibRouterosError

from .constants import DEFAULT_QUEUE_PRIORITY
from .exceptions import (
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
    UnsupportedQueueVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class QueueCredentials:
    """What an adapter needs to open a real connection -- resolved by the
    caller from the target ``Router``'s own connection fields, mirroring
    ``app.domains.provisioning_engine.device_adapters.DeviceCredentials``
    (minus SSH -- no queue operation needs a file transport, see module
    docstring)."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class QueueDeviceStatus:
    """Real, current device-side queue counters a successful
    ``read_queue_status()`` call returns."""

    device_queue_id: str
    name: str | None
    target: str | None
    disabled: bool
    bytes_uploaded: int | None
    bytes_downloaded: int | None
    packets_uploaded: int | None
    packets_downloaded: int | None
    queued_bytes: int | None


class BaseQueueAdapter(Protocol):
    """What a vendor implements to plug real bandwidth/QoS queue
    operations into the Queue Management Engine. A new vendor is exactly:
    implement this Protocol, register it (mirrors
    ``app.domains.provisioning_engine.device_adapters``'s own registry
    pattern)."""

    vendor: str

    async def create_simple_queue(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        target: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = DEFAULT_QUEUE_PRIORITY,
    ) -> str:
        """Creates a real ``/queue simple`` entry. Returns the device-side
        queue id."""
        ...

    async def update_simple_queue(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = DEFAULT_QUEUE_PRIORITY,
    ) -> None:
        """Updates an existing ``/queue simple`` entry's rate/burst/
        priority fields."""
        ...

    async def delete_simple_queue(
        self, credentials: QueueCredentials, *, device_queue_id: str
    ) -> None:
        """Removes a ``/queue simple`` entry entirely."""
        ...

    async def create_queue_tree(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        parent: str,
        packet_mark: str | None,
        max_limit_kbps: int,
        priority: int = DEFAULT_QUEUE_PRIORITY,
        queue_type_name: str | None = None,
    ) -> str:
        """Creates a real ``/queue tree`` entry. Returns the device-side
        queue id."""
        ...

    async def apply_pcq(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        rate_kbps: int,
        classifier: str = "dst-address",
    ) -> str:
        """Creates a real ``/queue type`` entry with ``kind=pcq`` (Per-
        Connection-Queue) -- a fair-sharing queue type a ``/queue tree``
        entry's own ``queue`` field can then reference. Returns the
        device-side queue-type id."""
        ...

    async def set_priority(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        priority: int,
        queue_kind: str = "simple",
    ) -> None:
        """Updates only the ``priority`` field of an existing simple queue
        or queue-tree entry."""
        ...

    async def assign_queue_to_target(
        self, credentials: QueueCredentials, *, device_queue_id: str, target: str
    ) -> None:
        """Updates only the ``target`` field of an existing ``/queue
        simple`` entry -- re-pointing it at a new IP/interface (e.g. a
        guest reconnecting with a new DHCP lease)."""
        ...

    async def remove_queue(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> None:
        """Removes a queue entry of either kind (``"simple"`` or
        ``"tree"``)."""
        ...

    async def read_queue_status(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> QueueDeviceStatus:
        """Reads real, current counters for one queue entry."""
        ...


class MikroTikQueueAdapter:
    """See module docstring for the full "real client code, untested
    end-to-end here" write-up."""

    vendor = "mikrotik"

    async def create_simple_queue(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        target: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = DEFAULT_QUEUE_PRIORITY,
    ) -> str:
        fields = {
            "name": name,
            "target": target,
            **_max_limit_field(upload_rate_kbps, download_rate_kbps),
            **_burst_fields(
                burst_upload_kbps,
                burst_download_kbps,
                burst_threshold_kbps,
                burst_time_seconds,
            ),
            "priority": str(priority),
        }
        return await asyncio.to_thread(
            self._add_sync,
            credentials,
            ("queue", "simple"),
            fields,
            "create_simple_queue",
        )

    async def update_simple_queue(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = DEFAULT_QUEUE_PRIORITY,
    ) -> None:
        fields = {
            ".id": device_queue_id,
            **_max_limit_field(upload_rate_kbps, download_rate_kbps),
            **_burst_fields(
                burst_upload_kbps,
                burst_download_kbps,
                burst_threshold_kbps,
                burst_time_seconds,
            ),
            "priority": str(priority),
        }
        await asyncio.to_thread(
            self._update_sync,
            credentials,
            ("queue", "simple"),
            fields,
            "update_simple_queue",
        )

    async def delete_simple_queue(
        self, credentials: QueueCredentials, *, device_queue_id: str
    ) -> None:
        await asyncio.to_thread(
            self._remove_sync,
            credentials,
            ("queue", "simple"),
            device_queue_id,
            "delete_simple_queue",
        )

    async def create_queue_tree(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        parent: str,
        packet_mark: str | None,
        max_limit_kbps: int,
        priority: int = DEFAULT_QUEUE_PRIORITY,
        queue_type_name: str | None = None,
    ) -> str:
        fields: dict[str, str] = {
            "name": name,
            "parent": parent,
            "max-limit": f"{max_limit_kbps}k",
            "priority": str(priority),
        }
        if packet_mark is not None:
            fields["packet-mark"] = packet_mark
        if queue_type_name is not None:
            fields["queue"] = queue_type_name
        return await asyncio.to_thread(
            self._add_sync, credentials, ("queue", "tree"), fields, "create_queue_tree"
        )

    async def apply_pcq(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        rate_kbps: int,
        classifier: str = "dst-address",
    ) -> str:
        fields = {
            "name": name,
            "kind": "pcq",
            "pcq-rate": f"{rate_kbps}k",
            "pcq-classifier": classifier,
        }
        return await asyncio.to_thread(
            self._add_sync, credentials, ("queue", "type"), fields, "apply_pcq"
        )

    async def set_priority(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        priority: int,
        queue_kind: str = "simple",
    ) -> None:
        fields = {".id": device_queue_id, "priority": str(priority)}
        await asyncio.to_thread(
            self._update_sync,
            credentials,
            ("queue", queue_kind),
            fields,
            "set_priority",
        )

    async def assign_queue_to_target(
        self, credentials: QueueCredentials, *, device_queue_id: str, target: str
    ) -> None:
        fields = {".id": device_queue_id, "target": target}
        await asyncio.to_thread(
            self._update_sync,
            credentials,
            ("queue", "simple"),
            fields,
            "assign_queue_to_target",
        )

    async def remove_queue(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> None:
        await asyncio.to_thread(
            self._remove_sync,
            credentials,
            ("queue", queue_kind),
            device_queue_id,
            "remove_queue",
        )

    async def read_queue_status(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> QueueDeviceStatus:
        return await asyncio.to_thread(
            self._read_status_sync, credentials, queue_kind, device_queue_id
        )

    # ========================================================================
    # Internal transport helpers
    # ========================================================================

    def _connect_api(self, credentials: QueueCredentials):  # noqa: ANN202
        try:
            return librouteros.connect(
                host=credentials.host,
                username=credentials.username,
                password=credentials.password,
                port=credentials.api_port,
                timeout=credentials.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise QueueDeviceConnectionError(credentials.host, str(exc)) from exc

    def _add_sync(
        self,
        credentials: QueueCredentials,
        path_segments: tuple[str, ...],
        fields: dict[str, str],
        operation: str,
    ) -> str:
        api = self._connect_api(credentials)
        try:
            return api.path(*path_segments).add(**fields)
        except LibRouterosError as exc:
            raise QueueDeviceOperationError(operation, str(exc)) from exc
        finally:
            api.close()

    def _update_sync(
        self,
        credentials: QueueCredentials,
        path_segments: tuple[str, ...],
        fields: dict[str, str],
        operation: str,
    ) -> None:
        api = self._connect_api(credentials)
        try:
            api.path(*path_segments).update(**fields)
        except LibRouterosError as exc:
            raise QueueDeviceOperationError(operation, str(exc)) from exc
        finally:
            api.close()

    def _remove_sync(
        self,
        credentials: QueueCredentials,
        path_segments: tuple[str, ...],
        device_queue_id: str,
        operation: str,
    ) -> None:
        api = self._connect_api(credentials)
        try:
            api.path(*path_segments).remove(device_queue_id)
        except LibRouterosError as exc:
            raise QueueDeviceOperationError(operation, str(exc)) from exc
        finally:
            api.close()

    def _read_status_sync(
        self, credentials: QueueCredentials, queue_kind: str, device_queue_id: str
    ) -> QueueDeviceStatus:
        api = self._connect_api(credentials)
        try:
            # Client-side filter over the full print result -- a router's
            # own queue table is small (at most a few hundred rows), so
            # this is a real, correct, easily-testable-via-fake-transport
            # implementation choice, not a shortcut.
            rows = list(api.path("queue", queue_kind))
            row = next((r for r in rows if r.get(".id") == device_queue_id), {})
        except LibRouterosError as exc:
            raise QueueDeviceOperationError("read_queue_status", str(exc)) from exc
        finally:
            api.close()
        return QueueDeviceStatus(
            device_queue_id=device_queue_id,
            name=row.get("name"),
            target=row.get("target"),
            disabled=str(row.get("disabled", "false")).lower() == "true",
            bytes_uploaded=_split_pair_int(row.get("bytes"), 0),
            bytes_downloaded=_split_pair_int(row.get("bytes"), 1),
            packets_uploaded=_split_pair_int(row.get("packets"), 0),
            packets_downloaded=_split_pair_int(row.get("packets"), 1),
            queued_bytes=_split_pair_int(row.get("queued-bytes"), 0),
        )


def _max_limit_field(upload_rate_kbps: int, download_rate_kbps: int) -> dict[str, str]:
    return {"max-limit": f"{upload_rate_kbps}k/{download_rate_kbps}k"}


def _burst_fields(
    burst_upload_kbps: int | None,
    burst_download_kbps: int | None,
    burst_threshold_kbps: int | None,
    burst_time_seconds: int | None,
) -> dict[str, str]:
    """RouterOS only accepts burst-limit/burst-threshold/burst-time as a
    trio -- if none of the three burst rate values is set, no burst fields
    are emitted at all (an unset burst is a real, valid RouterOS queue,
    not an error)."""
    if burst_upload_kbps is None and burst_download_kbps is None:
        return {}
    fields = {
        "burst-limit": f"{burst_upload_kbps or 0}k/{burst_download_kbps or 0}k",
    }
    if burst_threshold_kbps is not None:
        fields["burst-threshold"] = f"{burst_threshold_kbps}k/{burst_threshold_kbps}k"
    if burst_time_seconds is not None:
        fields["burst-time"] = f"{burst_time_seconds}/{burst_time_seconds}"
    return fields


def _split_pair_int(value: object, index: int) -> int | None:
    """RouterOS reports several counters (``bytes``, ``packets``,
    ``queued-bytes``) as an ``"upload/download"``-style pair string."""
    if not value:
        return None
    parts = str(value).split("/")
    if len(parts) <= index:
        return None
    try:
        return int(parts[index])
    except ValueError:
        return None


_QUEUE_ADAPTERS: dict[str, BaseQueueAdapter] = {"mikrotik": MikroTikQueueAdapter()}


def get_queue_adapter(vendor: str) -> BaseQueueAdapter:
    """Raises :class:`~.exceptions.UnsupportedQueueVendorError` if no
    adapter is registered for ``vendor``."""
    adapter = _QUEUE_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedQueueVendorError(vendor)
    return adapter


def list_supported_queue_vendors() -> list[str]:
    return sorted(_QUEUE_ADAPTERS)


__all__ = [
    "QueueCredentials",
    "QueueDeviceStatus",
    "BaseQueueAdapter",
    "MikroTikQueueAdapter",
    "get_queue_adapter",
    "list_supported_queue_vendors",
]

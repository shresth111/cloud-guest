"""Real device I/O adapters for the Queue Management Engine -- the
Strategy/Adapter seam that keeps this domain's own core engine
(``service.py``) completely vendor-agnostic. ``BaseQueueAdapter`` is what a
vendor implements to plug in real bandwidth/QoS queue operations; the
engine itself never imports ``librouteros`` or constructs a single
RouterOS command directly.

## Now delegates to wyfy-device-gateway

Per the ``wyfy-device-gateway`` PRD (section 7, Step 3, item 4),
``MikroTikQueueAdapter``'s nine methods (``create_simple_queue``,
``update_simple_queue``, ``delete_simple_queue``, ``create_queue_tree``,
``apply_pcq``, ``set_priority``, ``assign_queue_to_target``,
``remove_queue``, ``read_queue_status``) now call
``wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)``
instead of opening ``librouteros`` directly -- that package is a straight
port of this module's own former ``_add_sync``/``_update_sync``/
``_remove_sync``/``_read_status_sync`` methods, including the identical
RouterOS command shapes (same ``Path.add``/``.update``/``.remove`` calls),
the same rate/burst-field formatting (kbps with a ``k`` suffix,
upload/download pair strings via ``_max_limit_field``/``_burst_fields``),
and the same counter-pair parsing (``_split_pair_int``). Public
signatures/return shapes are unchanged; the gateway's
``MikroTikConnectionError``/``MikroTikDeviceError`` distinction is
translated back into this domain's own ``QueueDeviceConnectionError``/
``QueueDeviceOperationError`` pair so ``service.py`` needs no changes,
mirroring the identical pattern already used for the ``isp``,
``network_diagnostics``, and ``connected_devices`` call sites.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

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
    """See module docstring's "now delegates to wyfy-device-gateway"
    write-up."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: QueueCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

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
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).create_simple_queue(
                creds,
                name=name,
                target=target,
                download_rate_kbps=download_rate_kbps,
                upload_rate_kbps=upload_rate_kbps,
                burst_download_kbps=burst_download_kbps,
                burst_upload_kbps=burst_upload_kbps,
                burst_threshold_kbps=burst_threshold_kbps,
                burst_time_seconds=burst_time_seconds,
                priority=priority,
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("create_simple_queue", exc.detail) from exc

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
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).update_simple_queue(
                creds,
                device_queue_id=device_queue_id,
                download_rate_kbps=download_rate_kbps,
                upload_rate_kbps=upload_rate_kbps,
                burst_download_kbps=burst_download_kbps,
                burst_upload_kbps=burst_upload_kbps,
                burst_threshold_kbps=burst_threshold_kbps,
                burst_time_seconds=burst_time_seconds,
                priority=priority,
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("update_simple_queue", exc.detail) from exc

    async def delete_simple_queue(
        self, credentials: QueueCredentials, *, device_queue_id: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_simple_queue(
                creds, device_queue_id=device_queue_id
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("delete_simple_queue", exc.detail) from exc

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
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).create_queue_tree(
                creds,
                name=name,
                parent=parent,
                packet_mark=packet_mark,
                max_limit_kbps=max_limit_kbps,
                priority=priority,
                queue_type_name=queue_type_name,
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("create_queue_tree", exc.detail) from exc

    async def apply_pcq(
        self,
        credentials: QueueCredentials,
        *,
        name: str,
        rate_kbps: int,
        classifier: str = "dst-address",
    ) -> str:
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).apply_pcq(
                creds, name=name, rate_kbps=rate_kbps, classifier=classifier
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("apply_pcq", exc.detail) from exc

    async def set_priority(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        priority: int,
        queue_kind: str = "simple",
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).set_priority(
                creds,
                device_queue_id=device_queue_id,
                priority=priority,
                queue_kind=queue_kind,
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("set_priority", exc.detail) from exc

    async def assign_queue_to_target(
        self, credentials: QueueCredentials, *, device_queue_id: str, target: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).assign_queue_to_target(
                creds, device_queue_id=device_queue_id, target=target
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError(
                "assign_queue_to_target", exc.detail
            ) from exc

    async def remove_queue(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).remove_queue(
                creds, device_queue_id=device_queue_id, queue_kind=queue_kind
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("remove_queue", exc.detail) from exc

    async def read_queue_status(
        self,
        credentials: QueueCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> QueueDeviceStatus:
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).read_queue_status(
                creds, device_queue_id=device_queue_id, queue_kind=queue_kind
            )
        except MikroTikConnectionError as exc:
            raise QueueDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QueueDeviceOperationError("read_queue_status", exc.detail) from exc
        return QueueDeviceStatus(
            device_queue_id=result.device_queue_id,
            name=result.name,
            target=result.target,
            disabled=result.disabled,
            bytes_uploaded=result.bytes_uploaded,
            bytes_downloaded=result.bytes_downloaded,
            packets_uploaded=result.packets_uploaded,
            packets_downloaded=result.packets_downloaded,
            queued_bytes=result.queued_bytes,
        )


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

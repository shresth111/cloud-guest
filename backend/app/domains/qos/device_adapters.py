"""Real device I/O adapter for the QoS & VOIP Priority domain -- the piece
that was genuinely missing (see ``service.py``'s own module docstring for
the full "before/after" write-up).

## What this closes

``app.domains.network_config.renderers.render_qos_traffic_rule`` already
renders the real ``/ip firewall mangle ... action=mark-packet`` half of
RouterOS QoS, pushed to the device through
``app.domains.network_config.service.NetworkConfigService.push_config``'s
own real, already-working ``ConfigVersion``/``ProvisioningJob`` pipeline
(``POST /network-config/routers/{router_id}/push``) -- that path was
already real and reachable, not a gap. What had no real device effect at
all was the paired ``/queue tree`` entry that actually makes a packet
mark *do* anything (RouterOS realizes QoS as two independent steps: mark,
then a queue that references the mark -- a mark with no referencing queue
is inert). This module is that second step, a real, direct device push
mirroring ``app.domains.queue_management.device_adapters``'s own
established shape exactly:

* Its own narrow ``QosCredentials`` dataclass (mirrors ``QueueCredentials``).
* Its own ``BaseQosPriorityQueueAdapter`` Protocol (a **subset** of
  ``queue_management``'s ``BaseQueueAdapter`` -- only the three real
  ``wyfy_device_gateway`` operations this domain actually needs:
  ``create_queue_tree``, ``set_priority``, ``remove_queue``. This domain
  never creates a ``/queue simple`` entry, never calls ``apply_pcq``/
  ``assign_queue_to_target`` -- those remain ``queue_management``'s own
  concern, see this module's own "why a new, smaller adapter, not reuse of
  ``queue_management``'s" section below).
* A real ``MikroTikQosQueueAdapter`` delegating to
  ``wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)`` --
  the exact same gateway package ``queue_management.device_adapters``
  already delegates to, translating the gateway's
  ``MikroTikConnectionError``/``MikroTikDeviceError`` pair into this
  domain's own ``QosDeviceConnectionError``/``QosDeviceOperationError``,
  identical to every other real device-I/O call site in this codebase
  (``isp``, ``network_diagnostics``, ``connected_devices``,
  ``queue_management``).

## Why a new, small adapter here, not "just call queue_management's"

Cross-domain composition in this codebase happens at the *service* layer
via narrow, duck-typed Protocols (``RouterLookupProtocol``,
``PolicyLookupProtocol``, ...) -- never at the device_adapters layer.
Every domain that needs real device I/O (``isp``, ``network_diagnostics``,
``connected_devices``, ``queue_management``, and now this one) owns its
own thin ``device_adapters.py`` that calls the vendor gateway directly;
none of them import another domain's adapter instance. Reaching into
``queue_management.device_adapters.get_queue_adapter`` from here would be
the one call site in this codebase crossing that boundary, coupling this
domain's device I/O to ``queue_management``'s own registry/exception
types for no real benefit -- the actual shared code (the gateway package
itself, ``wyfy_device_gateway``) is already shared at the correct layer.
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

from .constants import (
    DEFAULT_PRIORITY,
    QOS_QUEUE_TREE_PARENT,
    QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS,
)
from .exceptions import (
    QosDeviceConnectionError,
    QosDeviceOperationError,
    UnsupportedQosVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class QosCredentials:
    """What an adapter needs to open a real connection -- resolved by the
    caller from the target ``Router``'s own connection fields. Mirrors
    ``app.domains.queue_management.device_adapters.QueueCredentials``
    field-for-field (a deliberately identical, independently-defined
    shape, not imported from that module -- see this module's own
    docstring for why the two domains' device-I/O layers stay
    uncoupled)."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


class BaseQosPriorityQueueAdapter(Protocol):
    """What a vendor implements to plug real priority-queue operations
    into the QoS & VOIP Priority domain. A new vendor is exactly: implement
    this Protocol, register it (mirrors
    ``app.domains.queue_management.device_adapters``'s own registry
    pattern)."""

    vendor: str

    async def create_priority_queue(
        self,
        credentials: QosCredentials,
        *,
        name: str,
        packet_mark: str,
        priority: int = DEFAULT_PRIORITY,
    ) -> str:
        """Creates a real ``/queue tree`` entry, parented at
        ``constants.QOS_QUEUE_TREE_PARENT`` and referencing
        ``packet_mark`` (a mangle mark this domain does not itself create
        -- see ``app.domains.network_config.renderers
        .render_qos_traffic_rule``), with ``max-limit`` fixed at
        ``constants.QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS`` (this domain
        tracks priority/classification only, never a bandwidth ceiling --
        see ``models.py``'s own "Scope" section). Returns the device-side
        queue id."""
        ...

    async def set_priority(
        self, credentials: QosCredentials, *, device_queue_id: str, priority: int
    ) -> None:
        """Updates only the ``priority`` field of an existing ``/queue
        tree`` entry -- the cheap re-push path when only a rule's
        ``priority`` changed and its packet-mark identifier (derived from
        ``name`` + row id, see ``identifiers.py``) did not."""
        ...

    async def remove_priority_queue(
        self, credentials: QosCredentials, *, device_queue_id: str
    ) -> None:
        """Removes a ``/queue tree`` entry entirely."""
        ...


class MikroTikQosQueueAdapter:
    """See module docstring for the full "now delegates to
    wyfy-device-gateway" write-up (identical delegation pattern to
    ``app.domains.queue_management.device_adapters.MikroTikQueueAdapter``,
    a smaller surface)."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: QosCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def create_priority_queue(
        self,
        credentials: QosCredentials,
        *,
        name: str,
        packet_mark: str,
        priority: int = DEFAULT_PRIORITY,
    ) -> str:
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).create_queue_tree(
                creds,
                name=name,
                parent=QOS_QUEUE_TREE_PARENT,
                packet_mark=packet_mark,
                max_limit_kbps=QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS,
                priority=priority,
                queue_type_name=None,
            )
        except MikroTikConnectionError as exc:
            raise QosDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QosDeviceOperationError("create_priority_queue", exc.detail) from exc

    async def set_priority(
        self, credentials: QosCredentials, *, device_queue_id: str, priority: int
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).set_priority(
                creds,
                device_queue_id=device_queue_id,
                priority=priority,
                queue_kind="tree",
            )
        except MikroTikConnectionError as exc:
            raise QosDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QosDeviceOperationError("set_priority", exc.detail) from exc

    async def remove_priority_queue(
        self, credentials: QosCredentials, *, device_queue_id: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).remove_queue(
                creds, device_queue_id=device_queue_id, queue_kind="tree"
            )
        except MikroTikConnectionError as exc:
            raise QosDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QosDeviceOperationError("remove_priority_queue", exc.detail) from exc


_QOS_QUEUE_ADAPTERS: dict[str, BaseQosPriorityQueueAdapter] = {
    "mikrotik": MikroTikQosQueueAdapter()
}


def get_qos_queue_adapter(vendor: str) -> BaseQosPriorityQueueAdapter:
    """Raises :class:`~.exceptions.UnsupportedQosVendorError` if no adapter
    is registered for ``vendor``."""
    adapter = _QOS_QUEUE_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedQosVendorError(vendor)
    return adapter


def list_supported_qos_vendors() -> list[str]:
    return sorted(_QOS_QUEUE_ADAPTERS)


__all__ = [
    "QosCredentials",
    "BaseQosPriorityQueueAdapter",
    "MikroTikQosQueueAdapter",
    "get_qos_queue_adapter",
    "list_supported_qos_vendors",
]

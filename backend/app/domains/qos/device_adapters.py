"""Real device I/O adapter for the QoS & VOIP Priority domain -- the piece
that was genuinely missing (see ``service.py``'s own module docstring for
the full "before/after" write-up).

## What this closes

RouterOS realizes QoS as two independent objects: an ``/ip firewall
mangle`` rule that *sets* a packet mark, and a ``/queue tree`` entry that
*references* it. Either one alone is inert.

This module now pushes **both**, because pushing one was worse than
pushing neither. ``app.domains.network_config.renderers
.render_qos_traffic_rule`` does render the mangle half, but only into a
config script applied by ``POST /network-config/routers/{router_id}/push``
-- an endpoint no customer surface calls and no scheduled job runs (see
``docs/qa/NETWORK_FEATURES_AUDIT.md`` §4). So a customer who clicked Apply
got a real queue tree matching zero packets, a row reading ``active``, and
a dashboard badge reading "Applied to your router". The queue's own device
id existing is exactly what made that state hard to doubt.

``apply_packet_mark``/``remove_packet_mark`` close the first half;
``create_priority_queue``/``set_priority``/``remove_priority_queue`` are
the second. Both are real, direct device pushes mirroring
``app.domains.queue_management.device_adapters``'s own established shape
exactly:

* Its own narrow ``QosCredentials`` dataclass (mirrors ``QueueCredentials``).
* Its own ``BaseQosPriorityQueueAdapter`` Protocol (a **subset** of
  ``queue_management``'s ``BaseQueueAdapter`` -- only the three real
  ``wyfy_device_gateway`` operations this domain actually needs:
  ``create_queue_tree``, ``set_priority``, ``remove_queue``, plus the two
  ``configure_qos_packet_mark``/``delete_qos_packet_mark`` writers this
  domain's own gap required. This domain
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
from wyfy_device_gateway.contract import DeviceVendor, QosPacketMarkConfig
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
        ``packet_mark`` -- the mark :meth:`apply_packet_mark` puts on the
        device in the same push, derived from one source of truth
        (``identifiers.qos_packet_mark_identifier``) so the two objects can
        never reference different strings -- with ``max-limit`` fixed at
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

    async def apply_packet_mark(
        self,
        credentials: QosCredentials,
        *,
        rule_id: str,
        packet_mark: str,
        label: str,
        priority: int,
        protocol: str | None,
        port_range_start: int | None,
        port_range_end: int | None,
        dscp_value: int | None,
    ) -> None:
        """Creates or updates the real ``/ip firewall mangle`` rule that
        *sets* ``packet_mark`` -- the half of RouterOS QoS the queue tree
        references. Idempotent on ``rule_id``; see the gateway's own
        ``configure_qos_packet_mark`` docstring for the identity-by-comment
        design and for what it deliberately does not claim about the rule's
        position in the ``prerouting`` chain."""
        ...

    async def remove_packet_mark(
        self, credentials: QosCredentials, *, rule_id: str
    ) -> None:
        """Removes that mangle rule, by the same ``rule_id`` identity the
        write path stamps it with. Idempotent."""
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

    async def apply_packet_mark(
        self,
        credentials: QosCredentials,
        *,
        rule_id: str,
        packet_mark: str,
        label: str,
        priority: int,
        protocol: str | None,
        port_range_start: int | None,
        port_range_end: int | None,
        dscp_value: int | None,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_qos_packet_mark(
                creds,
                rule=QosPacketMarkConfig(
                    rule_id=rule_id,
                    packet_mark=packet_mark,
                    label=label,
                    priority=priority,
                    protocol=protocol,
                    port_range_start=port_range_start,
                    port_range_end=port_range_end,
                    dscp_value=dscp_value,
                ),
            )
        except MikroTikConnectionError as exc:
            raise QosDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QosDeviceOperationError("apply_packet_mark", exc.detail) from exc

    async def remove_packet_mark(
        self, credentials: QosCredentials, *, rule_id: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_qos_packet_mark(
                creds, rule_id=rule_id
            )
        except MikroTikConnectionError as exc:
            raise QosDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise QosDeviceOperationError("remove_packet_mark", exc.detail) from exc


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

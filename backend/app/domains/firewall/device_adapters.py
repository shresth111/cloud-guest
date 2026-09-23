"""Real device I/O for the Firewall Rule Management domain.

## What this closes

This domain wrote a ``FirewallRule`` row, returned 201, and stopped. Its only
device path was ``network_config``'s rendered script shipped by SFTP +
``/import`` over port 22 -- which the fleet filters -- so no firewall rule
created here has ever reached a router. The Security capability matrix
could not honestly call zone-to-zone firewalling available while that was
true.

## Shape

Mirrors ``app.domains.content_filtering.device_adapters``: an own narrow
credentials dataclass, a Protocol naming only what this domain needs, a
MikroTik implementation delegating to ``wyfy_device_gateway``, and a vendor
registry that refuses anything else. The ordering algorithm, the sentinel
band and every refusal live in
``wyfy_device_gateway.mikrotik_firewall``; this layer only translates the
gateway's exceptions into this domain's typed, status-coded ones.

MikroTik only. There is no Omada path here, deliberately: a controller-
managed venue is refused by the service before this module is reached, and
the registry below has no entry for it either.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import (
    DeviceVendor,
    FirewallBandResult,
    FirewallBandStatus,
    FirewallFilterRuleConfig,
    FirewallSyncResult,
)
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
    MikroTikFirewallPushFailedError,
    MikroTikFirewallRefusedError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    FirewallDeviceConnectionError,
    FirewallDeviceOperationError,
    FirewallPushFailedError,
    FirewallPushRefusedError,
    UnsupportedFirewallVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class FirewallCredentials:
    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


class BaseFirewallAdapter(Protocol):
    vendor: str

    async def sync_firewall_rules(
        self,
        credentials: FirewallCredentials,
        *,
        rules: Sequence[FirewallFilterRuleConfig],
        known_rule_ids: Sequence[str],
    ) -> FirewallSyncResult:
        """Converge the router's platform firewall rules onto ``rules``, the
        complete desired set, inside the sentinel band."""
        ...

    async def install_firewall_band(
        self, credentials: FirewallCredentials
    ) -> FirewallBandResult:
        """Place the forward-chain sentinel band once; leave an existing one
        exactly where it is."""
        ...

    async def read_firewall_band_status(
        self, credentials: FirewallCredentials
    ) -> FirewallBandStatus:
        """Read-only: ``ready`` / ``missing`` / ``invalid`` plus a reason
        code, from the same band inspector the push uses."""
        ...


class MikroTikFirewallAdapter:
    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: FirewallCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def sync_firewall_rules(
        self,
        credentials: FirewallCredentials,
        *,
        rules: Sequence[FirewallFilterRuleConfig],
        known_rule_ids: Sequence[str],
    ) -> FirewallSyncResult:
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).sync_firewall_rules(
                self._gateway_credentials(credentials),
                rules=rules,
                known_rule_ids=known_rule_ids,
            )
        except MikroTikConnectionError as exc:
            raise FirewallDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikFirewallRefusedError as exc:
            raise FirewallPushRefusedError(exc.code, exc.detail) from exc
        except MikroTikFirewallPushFailedError as exc:
            raise FirewallPushFailedError(exc.detail, restored=exc.restored) from exc
        except MikroTikDeviceError as exc:
            raise FirewallDeviceOperationError(
                "sync_firewall_rules", exc.detail
            ) from exc

    async def install_firewall_band(
        self, credentials: FirewallCredentials
    ) -> FirewallBandResult:
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).install_firewall_band(
                self._gateway_credentials(credentials)
            )
        except MikroTikConnectionError as exc:
            raise FirewallDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikFirewallRefusedError as exc:
            raise FirewallPushRefusedError(exc.code, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise FirewallDeviceOperationError(
                "install_firewall_band", exc.detail
            ) from exc

    async def read_firewall_band_status(
        self, credentials: FirewallCredentials
    ) -> FirewallBandStatus:
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).read_firewall_band_status(
                self._gateway_credentials(credentials)
            )
        except MikroTikConnectionError as exc:
            raise FirewallDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise FirewallDeviceOperationError(
                "read_firewall_band_status", exc.detail
            ) from exc


_FIREWALL_ADAPTERS: dict[str, BaseFirewallAdapter] = {
    "mikrotik": MikroTikFirewallAdapter()
}


def get_firewall_adapter(vendor: str) -> BaseFirewallAdapter:
    adapter = _FIREWALL_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedFirewallVendorError(vendor)
    return adapter


__all__ = [
    "BaseFirewallAdapter",
    "FirewallCredentials",
    "MikroTikFirewallAdapter",
    "get_firewall_adapter",
]

"""Vendor-agnostic network device gateway for Wyfy Guest.

Public surface: import types from ``wyfy_device_gateway.contract`` and call
``wyfy_device_gateway.registry.get_adapter`` / ``list_supported_vendors``.
Re-exported here for convenience.
"""

from __future__ import annotations

from .contract import (
    ConnectedDevice,
    DeviceCredentials,
    DeviceGatewayAdapter,
    DeviceVendor,
    DhcpPoolConfig,
    InterfaceInfo,
    PortForwardConfig,
    ProvisionResult,
    RadiusClientConfig,
    UnsupportedVendorError,
    VlanConfig,
    WanHealth,
)
from .read_only_reader import (
    READ_ONLY_SECTION_PATHS,
    ReadOnlyDeviceReader,
    ReadOnlyStateCapture,
    ReadOnlyViolationError,
)
from .registry import get_adapter, list_supported_vendors

__all__ = [
    "ConnectedDevice",
    "DeviceCredentials",
    "DeviceGatewayAdapter",
    "DeviceVendor",
    "DhcpPoolConfig",
    "InterfaceInfo",
    "PortForwardConfig",
    "ProvisionResult",
    "READ_ONLY_SECTION_PATHS",
    "RadiusClientConfig",
    "ReadOnlyDeviceReader",
    "ReadOnlyStateCapture",
    "ReadOnlyViolationError",
    "UnsupportedVendorError",
    "VlanConfig",
    "WanHealth",
    "get_adapter",
    "list_supported_vendors",
]

__version__ = "0.1.0"

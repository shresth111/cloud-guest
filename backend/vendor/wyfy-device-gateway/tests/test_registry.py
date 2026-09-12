from __future__ import annotations

import pytest

from wyfy_device_gateway.contract import DeviceGatewayAdapter, DeviceVendor, UnsupportedVendorError
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter
from wyfy_device_gateway.registry import get_adapter, list_supported_vendors


def test_list_supported_vendors_includes_every_declared_vendor():
    assert list_supported_vendors() == sorted(DeviceVendor, key=lambda v: v.value)


def test_get_adapter_returns_real_mikrotik_adapter():
    adapter = get_adapter(DeviceVendor.MIKROTIK)
    assert isinstance(adapter, MikroTikAdapter)
    assert isinstance(adapter, DeviceGatewayAdapter)
    assert adapter.capabilities()["get_interface_list"] is True


def test_get_adapter_returns_stub_for_unimplemented_vendor():
    adapter = get_adapter(DeviceVendor.UNIFI)
    assert all(value is False for value in adapter.capabilities().values())


def test_get_adapter_raises_for_unregistered_vendor():
    with pytest.raises(UnsupportedVendorError):
        get_adapter("not_a_real_vendor")  # type: ignore[arg-type]

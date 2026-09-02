from __future__ import annotations

from typing import Any

import pytest

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor


@pytest.fixture
def mikrotik_creds() -> DeviceCredentials:
    return DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host="10.0.0.1",
        username="admin",
        secret="hunter2",
    )


@pytest.fixture
def patch_connect(monkeypatch: pytest.MonkeyPatch):
    """Patches ``wyfy_device_gateway.mikrotik_adapter.librouteros.connect``
    to return the given fake api object (or raise, if given an exception
    instance) -- never opens a real socket. Returns a setter function so
    each test can install whatever fake transport/behavior it needs."""
    import wyfy_device_gateway.mikrotik_adapter as mikrotik_adapter_module

    def _set(api_or_exception: Any) -> None:
        def _fake_connect(**kwargs: Any):
            if isinstance(api_or_exception, BaseException):
                raise api_or_exception
            return api_or_exception

        monkeypatch.setattr(mikrotik_adapter_module.librouteros, "connect", _fake_connect)

    return _set

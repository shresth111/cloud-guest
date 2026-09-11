"""Reboot-via-connection-reset semantics, ported from
``router/device_adapters.py::_reboot_sync``: a connection-reset/timeout
while reading the reply to ``/system reboot`` is the *expected* success
case, not a failure. Only a failure to open the connection at all is a
real error."""

from __future__ import annotations

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError


@pytest.mark.asyncio
async def test_reboot_normal_reply_succeeds(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(menus={("system", "reboot"): []})
    patch_connect(api)

    await MikroTikAdapter().reboot_device(mikrotik_creds)

    assert api.closed is True


@pytest.mark.asyncio
async def test_reboot_connection_reset_is_treated_as_success(patch_connect, mikrotik_creds):
    class ResetOnCallPath:
        def __call__(self, **kwargs):
            raise EOFError("connection reset by device")

    class ResetApi(FakeRouterOSApi):
        def path(self, *segments):
            if segments == ("system", "reboot"):
                return ResetOnCallPath()
            return super().path(*segments)

    api = ResetApi()
    patch_connect(api)

    # Must not raise -- a reset mid-reboot-command is success, not failure.
    await MikroTikAdapter().reboot_device(mikrotik_creds)


@pytest.mark.asyncio
async def test_reboot_connect_failure_raises(patch_connect, mikrotik_creds):
    patch_connect(LibRouterosError("bad credentials"))

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().reboot_device(mikrotik_creds)

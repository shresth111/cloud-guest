"""Device side of the router's local ``admin`` password.

Everything here runs over the RouterOS API (8728). The older
``device_credential_rotator`` sends ``/user set [find ...]``, which
``MikroTikAdapter.execute_raw_command`` can only run over SSH, and port 22 does
not reach this fleet.
"""

from __future__ import annotations

import secrets
import string
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.mikrotik_local_users import (
    LocalUser,
    LocalUserNotFoundError,
    LoginProbeResult,
)
from wyfy_device_gateway.registry import get_adapter

LOCAL_ADMIN_USERNAME = "admin"
LOCAL_ADMIN_STATUS_PENDING = "pending"
LOCAL_ADMIN_STATUS_ACTIVE = "active"

_API_PORT = 8728
_TIMEOUT_SECONDS = 10
# Letters and digits only: this value is pasted into a RouterOS script and typed
# by technicians, so it must not need escaping. Look-alike characters are left
# out because it gets read off a screen.
_ALPHABET = "".join(c for c in string.ascii_letters + string.digits if c not in "0O1lI")
_PASSWORD_LENGTH = 20


def generate_local_admin_password() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(_PASSWORD_LENGTH))


class LocalAdminDeviceError(Exception):
    """The device could not be reached or refused the operation."""


class LocalAdminDeviceProtocol(Protocol):
    async def probe_login(
        self, *, host: str, username: str, password: str
    ) -> LoginProbeResult: ...

    async def list_users(
        self, *, host: str, username: str, password: str
    ) -> list[LocalUser]: ...

    async def set_password(
        self,
        *,
        host: str,
        username: str,
        password: str,
        target_username: str,
        new_password: str,
    ) -> None: ...


def _creds(host: str, username: str, password: str) -> DeviceCredentials:
    return DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host=host,
        username=username,
        secret=password,
        port=_API_PORT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )


class GatewayLocalAdminDevice:
    """Real implementation. Stateless singleton."""

    async def probe_login(
        self, *, host: str, username: str, password: str
    ) -> LoginProbeResult:
        adapter = get_adapter(DeviceVendor.MIKROTIK)
        return await adapter.probe_api_login(_creds(host, username, password))

    async def list_users(
        self, *, host: str, username: str, password: str
    ) -> list[LocalUser]:
        adapter = get_adapter(DeviceVendor.MIKROTIK)
        try:
            return await adapter.list_local_users(_creds(host, username, password))
        except (MikroTikConnectionError, MikroTikDeviceError) as exc:
            raise LocalAdminDeviceError(exc.detail) from exc

    async def set_password(
        self,
        *,
        host: str,
        username: str,
        password: str,
        target_username: str,
        new_password: str,
    ) -> None:
        adapter = get_adapter(DeviceVendor.MIKROTIK)
        try:
            await adapter.set_local_user_password(
                _creds(host, username, password),
                username=target_username,
                new_password=new_password,
            )
        except (MikroTikConnectionError, MikroTikDeviceError) as exc:
            raise LocalAdminDeviceError(exc.detail) from exc
        except LocalUserNotFoundError as exc:
            raise LocalAdminDeviceError(f"no '{exc}' account on the device") from exc

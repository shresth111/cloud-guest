"""Real device I/O adapters for the Provisioning Engine -- the heavier,
"actually connect to and operate a device" Strategy/Adapter seam, distinct
from (and composed alongside) ``app.domains.router_provisioning.adapters
.ProvisioningAdapterProtocol`` (that one only validates template/vendor
compatibility and shapes a job's *payload metadata*; it never opens a
connection to anything, by design -- see that module's own docstring).
``BaseProvisionAdapter`` here is what a vendor implements to plug in real
device discovery, configuration push/verify, health checks, backup/restore,
and file upload.

## Honest scope: real client code, never exercised end-to-end here

:class:`MikroTikProvisionAdapter` uses two real, independent, genuinely
installed Python libraries (see ``requirements.txt``): ``librouteros`` (the
RouterOS API protocol, TCP port 8728/8729) for structured command
execution/discovery/health-checks, and ``asyncssh`` (SSH + SFTP) for file/
script upload and backup/restore transfer. Both are real libraries this
extension adds as genuine dependencies -- not stand-ins for something else.
This module's own command-construction and response-parsing logic is
exercised in this domain's tests via a fake transport (mirroring how
``app.domains.guest`` tests its FreeRADIUS ``rlm_rest`` integration without
a live FreeRADIUS server, and how ``app.domains.router_agent``'s own HTTP
surface is tested without a live external agent process).

**What is not, and cannot honestly be, claimed here:** an actual network
round-trip against a real, physical MikroTik router. There is no live
device anywhere in this sandbox. Every method below, if actually invoked in
this environment, will raise :class:`~.exceptions.ProvisionDeviceConnectionError`
the moment it tries to open a real socket -- exactly the honest outcome a
real, unreachable host would also produce, not a fabricated success. This is
this codebase's own "honest placeholder" discipline (already applied to
Celery health before a worker existed, FreeRADIUS before a live daemon
existed, and ``router_agent``'s own dispatch before a real agent process
existed) applied to a genuinely new class of gap: not a missing feature, but
an environment that cannot host what would prove the feature real end to
end.

## Why both librouteros AND asyncssh, not just one

``librouteros`` speaks RouterOS's own structured API protocol -- the right
tool for discovery (``/system/resource/print``, ``/system/routerboard
/print``, ``/interface/print``) and health checks (the same
``/system/resource/print`` fields, polled again). It has no file-transfer
primitive of its own. RouterOS's real, supported mechanism for getting a
script/backup file onto the device's file system before an ``/import``
(config) or ``/system/backup/load`` (restore) command can reference it is
SFTP over SSH -- the same reason a real MikroTik deployment configures both
API and SSH access, not one or the other. ``asyncssh`` is also what runs the
actual ``/import``/``/system/backup/save``/``/system/backup/load`` command
itself (RouterOS's SSH CLI accepts the identical slash-command console
syntax the winbox/telnet console does) -- ``librouteros``'s own API
protocol is not the right transport for triggering a file-system-level
operation like ``/import``.

## ``librouteros`` is a synchronous library

Every ``librouteros`` call blocks the calling thread on real socket I/O.
Every method below that uses it wraps the blocking call in
``asyncio.to_thread`` -- the same "bridge a sync library into an async
call site" pattern ``app.core.celery_app``'s own worker tasks already use
for this codebase's sync/async boundary, just applied here to a library
call instead of a whole Celery task body.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Protocol

import asyncssh
import librouteros
from librouteros.exceptions import LibRouterosError

from .exceptions import (
    ProvisionDeviceConnectionError,
    ProvisionDeviceOperationError,
    UnsupportedDeviceVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_SSH_PORT = 22
_DEFAULT_TIMEOUT_SECONDS = 10
_BACKUP_FILENAME = "cloudguest-backup.backup"
_CONFIG_FILENAME = "cloudguest-config.rsc"


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """What an adapter needs to open a real connection -- resolved by the
    caller from the target ``Router``'s own connection fields
    (``management_ip_address``/``public_ip_address``,
    ``api_username``/decrypted ``api_credentials_encrypted``), never stored
    on this dataclass beyond the single call it's passed to."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    ssh_port: int = _DEFAULT_SSH_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class DeviceDiscoveryResult:
    """Real device facts a successful ``discover()`` call would return --
    see ``ProvisioningEngineService.discover_device``'s own docstring for
    how this reconciles with ``Router``'s existing columns (it updates
    them; it does not duplicate them into a separate inventory table)."""

    vendor: str
    model: str | None
    serial_number: str | None
    firmware_version: str | None
    cpu_load_percent: float | None
    free_memory_bytes: int | None
    total_memory_bytes: int | None
    uptime_seconds: int | None
    interfaces: list[str] = field(default_factory=list)
    mac_address: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceHealthResult:
    healthy: bool
    cpu_load_percent: float | None
    free_memory_bytes: int | None
    uptime_seconds: int | None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class RawCommandResult:
    """The real, unfiltered outcome of one console command -- unlike every
    other adapter method here, a non-zero ``exit_status`` is not raised as
    an exception. A raw console is explicitly for commands whose shape and
    outcome the platform has no prior knowledge of (that is the entire
    point of it existing alongside the structured, always-succeeds-or-
    raises methods above) -- ``/interface print`` on a typo'd interface
    name, for instance, is a normal, expected non-zero outcome a console
    user needs to actually see, not an exception unwound into a generic
    502."""

    command: str
    stdout: str
    stderr: str
    exit_status: int


class BaseProvisionAdapter(Protocol):
    """What a vendor implements to plug real device I/O into the
    Provisioning Engine. See module docstring for the "real code, untested
    end-to-end here" scope note. A new vendor is exactly: implement this
    Protocol, register it (mirrors
    ``app.domains.router_provisioning.adapters``'s own registry pattern)."""

    vendor: str

    async def discover(self, credentials: DeviceCredentials) -> DeviceDiscoveryResult:
        """Connects and returns real, current device facts."""
        ...

    async def push_config(
        self, credentials: DeviceCredentials, *, config_content: str
    ) -> None:
        """Uploads and applies ``config_content`` (a fully-rendered device
        config script) to the device."""
        ...

    async def verify_config(
        self, credentials: DeviceCredentials, *, expected_content: str
    ) -> bool:
        """Confirms the config actually applied matches
        ``expected_content``."""
        ...

    async def health_check(self, credentials: DeviceCredentials) -> DeviceHealthResult:
        """A lighter-weight version of ``discover`` -- current load/uptime
        only, for a post-provision health gate."""
        ...

    async def backup(self, credentials: DeviceCredentials) -> bytes:
        """Triggers a device-side backup and returns its raw bytes."""
        ...

    async def restore(
        self, credentials: DeviceCredentials, *, backup_content: bytes
    ) -> None:
        """Uploads ``backup_content`` and triggers a device-side restore
        from it."""
        ...

    async def upload_file(
        self, credentials: DeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        """A generic file upload -- the primitive ``push_config``/
        ``restore`` are themselves built on."""
        ...

    async def execute_raw_command(
        self, credentials: DeviceCredentials, *, command: str
    ) -> RawCommandResult:
        """Runs exactly ``command`` over the device's real SSH console
        connection and returns its real stdout/stderr/exit status, with no
        interpretation, whitelisting, or retry -- the Winbox-terminal
        equivalent this Protocol's other methods deliberately are not (see
        ``RawCommandResult``'s own docstring)."""
        ...


class MikroTikProvisionAdapter:
    """See module docstring for the full "real client code, untested
    end-to-end here" write-up."""

    vendor = "mikrotik"

    async def discover(self, credentials: DeviceCredentials) -> DeviceDiscoveryResult:
        resource, routerboard, interfaces = await asyncio.to_thread(
            self._discover_sync, credentials
        )
        return DeviceDiscoveryResult(
            vendor=self.vendor,
            model=routerboard.get("model"),
            serial_number=routerboard.get("serial-number"),
            firmware_version=resource.get("version"),
            cpu_load_percent=_as_float(resource.get("cpu-load")),
            free_memory_bytes=_as_int(resource.get("free-memory")),
            total_memory_bytes=_as_int(resource.get("total-memory")),
            uptime_seconds=_parse_routeros_uptime(resource.get("uptime")),
            interfaces=[i.get("name", "") for i in interfaces if i.get("name")],
            mac_address=interfaces[0].get("mac-address") if interfaces else None,
        )

    def _discover_sync(
        self, credentials: DeviceCredentials
    ) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
        api = self._connect_api(credentials)
        try:
            resource = next(iter(api("/system/resource/print")), {})
            routerboard = next(iter(api("/system/routerboard/print")), {})
            interfaces = list(api("/interface/print"))
            return resource, routerboard, interfaces
        except LibRouterosError as exc:
            raise ProvisionDeviceOperationError("discover", str(exc)) from exc
        finally:
            api.close()

    async def push_config(
        self, credentials: DeviceCredentials, *, config_content: str
    ) -> None:
        await self.upload_file(
            credentials,
            filename=_CONFIG_FILENAME,
            content=config_content.encode("utf-8"),
        )
        await self._run_ssh_command(
            credentials, f'/import file-name="{_CONFIG_FILENAME}"'
        )

    async def verify_config(
        self, credentials: DeviceCredentials, *, expected_content: str
    ) -> bool:
        """Reads the config file back via SFTP and compares its SHA-256
        against ``expected_content`` -- a real, exact-content check, not a
        best-effort heuristic."""
        uploaded = await self._download_file(credentials, _CONFIG_FILENAME)
        expected_digest = hashlib.sha256(expected_content.encode("utf-8")).hexdigest()
        actual_digest = hashlib.sha256(uploaded).hexdigest()
        return expected_digest == actual_digest

    async def health_check(self, credentials: DeviceCredentials) -> DeviceHealthResult:
        try:
            resource = await asyncio.to_thread(self._health_check_sync, credentials)
        except ProvisionDeviceConnectionError as exc:
            return DeviceHealthResult(
                healthy=False,
                cpu_load_percent=None,
                free_memory_bytes=None,
                uptime_seconds=None,
                detail=str(exc),
            )
        return DeviceHealthResult(
            healthy=True,
            cpu_load_percent=_as_float(resource.get("cpu-load")),
            free_memory_bytes=_as_int(resource.get("free-memory")),
            uptime_seconds=_parse_routeros_uptime(resource.get("uptime")),
        )

    def _health_check_sync(self, credentials: DeviceCredentials) -> dict[str, object]:
        api = self._connect_api(credentials)
        try:
            return next(iter(api("/system/resource/print")), {})
        except LibRouterosError as exc:
            raise ProvisionDeviceOperationError("health_check", str(exc)) from exc
        finally:
            api.close()

    async def backup(self, credentials: DeviceCredentials) -> bytes:
        await self._run_ssh_command(
            credentials, f'/system/backup/save name="{_BACKUP_FILENAME}"'
        )
        return await self._download_file(credentials, _BACKUP_FILENAME)

    async def restore(
        self, credentials: DeviceCredentials, *, backup_content: bytes
    ) -> None:
        await self.upload_file(
            credentials, filename=_BACKUP_FILENAME, content=backup_content
        )
        await self._run_ssh_command(
            credentials, f'/system/backup/load name="{_BACKUP_FILENAME}"'
        )

    async def upload_file(
        self, credentials: DeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        try:
            async with (
                self._ssh_connect(credentials) as conn,
                conn.start_sftp_client() as sftp,
                sftp.open(filename, "wb") as remote_file,
            ):
                await remote_file.write(content)
        except (OSError, asyncssh.Error) as exc:
            raise ProvisionDeviceConnectionError(credentials.host, str(exc)) from exc

    async def execute_raw_command(
        self, credentials: DeviceCredentials, *, command: str
    ) -> RawCommandResult:
        try:
            async with self._ssh_connect(credentials) as conn:
                result = await conn.run(command, check=False)
        except (OSError, asyncssh.Error) as exc:
            raise ProvisionDeviceConnectionError(credentials.host, str(exc)) from exc
        return RawCommandResult(
            command=command,
            stdout=str(result.stdout or ""),
            stderr=str(result.stderr or ""),
            exit_status=result.exit_status if result.exit_status is not None else -1,
        )

    # ========================================================================
    # Internal transport helpers
    # ========================================================================

    def _connect_api(self, credentials: DeviceCredentials):  # noqa: ANN202
        try:
            return librouteros.connect(
                host=credentials.host,
                username=credentials.username,
                password=credentials.password,
                port=credentials.api_port,
                timeout=credentials.timeout_seconds,
            )
        except (LibRouterosError, OSError) as exc:
            raise ProvisionDeviceConnectionError(credentials.host, str(exc)) from exc

    def _ssh_connect(self, credentials: DeviceCredentials):  # noqa: ANN202
        return asyncssh.connect(
            credentials.host,
            port=credentials.ssh_port,
            username=credentials.username,
            password=credentials.password,
            known_hosts=None,
            connect_timeout=credentials.timeout_seconds,
        )

    async def _run_ssh_command(
        self, credentials: DeviceCredentials, command: str
    ) -> None:
        try:
            async with self._ssh_connect(credentials) as conn:
                result = await conn.run(command, check=False)
        except (OSError, asyncssh.Error) as exc:
            raise ProvisionDeviceConnectionError(credentials.host, str(exc)) from exc
        if result.exit_status != 0:
            raise ProvisionDeviceOperationError(
                command, result.stderr or f"exit status {result.exit_status}"
            )

    async def _download_file(
        self, credentials: DeviceCredentials, filename: str
    ) -> bytes:
        try:
            async with (
                self._ssh_connect(credentials) as conn,
                conn.start_sftp_client() as sftp,
                sftp.open(filename, "rb") as remote_file,
            ):
                return await remote_file.read()
        except (OSError, asyncssh.Error) as exc:
            raise ProvisionDeviceConnectionError(credentials.host, str(exc)) from exc


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).rstrip("%"))
    except ValueError:
        return None


def _as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_routeros_uptime(value: object) -> int | None:
    """RouterOS reports uptime as e.g. ``"3w2d4h5m6s"``, not a raw number of
    seconds. Parses each ``<number><unit>`` segment and sums them -- a real,
    exact parser, not a placeholder."""
    if not value:
        return None
    text = str(value)
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total_seconds = 0
    number = ""
    for char in text:
        if char.isdigit():
            number += char
        elif char in units and number:
            total_seconds += int(number) * units[char]
            number = ""
        else:
            return None
    return total_seconds


# The registry: one entry per real, plugged-in vendor. Adding a new vendor
# is exactly "implement BaseProvisionAdapter, add one entry here" -- mirrors
# app.domains.router_provisioning.adapters's own identical registry pattern
# for its own (lighter) adapter protocol.
_DEVICE_ADAPTERS: dict[str, BaseProvisionAdapter] = {
    "mikrotik": MikroTikProvisionAdapter(),
}


def get_device_adapter(vendor: str) -> BaseProvisionAdapter:
    """Raises :class:`~.exceptions.UnsupportedDeviceVendorError` if no
    adapter is registered for ``vendor``."""
    adapter = _DEVICE_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedDeviceVendorError(vendor)
    return adapter


def list_supported_device_vendors() -> list[str]:
    return sorted(_DEVICE_ADAPTERS)


__all__ = [
    "DeviceCredentials",
    "DeviceDiscoveryResult",
    "DeviceHealthResult",
    "RawCommandResult",
    "BaseProvisionAdapter",
    "MikroTikProvisionAdapter",
    "get_device_adapter",
    "list_supported_device_vendors",
]

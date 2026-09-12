"""Real device I/O adapters for the Provisioning Engine -- the heavier,
"actually connect to and operate a device" Strategy/Adapter seam, distinct
from (and composed alongside) ``app.domains.router_provisioning.adapters
.ProvisioningAdapterProtocol`` (that one only validates template/vendor
compatibility and shapes a job's *payload metadata*; it never opens a
connection to anything, by design -- see that module's own docstring).
``BaseProvisionAdapter`` here is what a vendor implements to plug in real
device discovery, configuration push/verify, health checks, backup/restore,
and file upload.

## Now delegates to wyfy-device-gateway

Per the ``wyfy-device-gateway`` PRD (section 7, Step 3, item 5 -- the
biggest-blast-radius call site, migrated last, once the pattern had proven
itself four times over on ``network_diagnostics``/``isp``/
``connected_devices``/``queue_management``), ``MikroTikProvisionAdapter``'s
methods (``discover``, ``push_config``, ``verify_config``, ``health_check``,
``backup``, ``restore``, ``upload_file``, ``execute_raw_command``) now call
``wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)`` instead
of opening ``librouteros``/``asyncssh`` directly. That package is a straight
port of this module's own real logic -- including the exact same
round-tripped filenames (``cloudguest-config.rsc``/``cloudguest-backup
.backup``) ``push_config``/``verify_config`` and ``backup``/``restore``
depend on staying in sync with each other, the same SHA-256
content-comparison ``verify_config`` uses, ``RawCommandResult``'s own
"never raises on non-zero exit status" contract, and -- the one genuinely
subtle behavior in this domain -- ``health_check``'s real distinction
between a *connection* failure (caught by the gateway's own
``health_check`` and reported as a graceful ``healthy=False`` result) and a
post-connection *operation* failure (which the gateway's ``health_check``
deliberately does NOT catch, so it propagates here and must be translated
into a real ``ProvisionDeviceOperationError``, never silently swallowed
into a fake "unhealthy" result). See
``wyfy_device_gateway.mikrotik_adapter.MikroTikAdapter.health_check``'s own
docstring for that same distinction, ported faithfully.

Public signatures/return shapes are unchanged; the gateway's
``MikroTikConnectionError``/``MikroTikDeviceError`` distinction is
translated back into this domain's own
``ProvisionDeviceConnectionError``/``ProvisionDeviceOperationError`` pair,
using the public method name as the operation label -- exactly the
convention already established by the ``isp``/``connected_devices``
migrations (e.g. ``"ping"``, ``"disconnect_device"``), not the raw
RouterOS/SSH command string the original sometimes used.

## Why both librouteros AND asyncssh, not just one (preserved context)

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
operation like ``/import``. This reasoning now lives with the real
transport code in ``wyfy_device_gateway.mikrotik_adapter``; kept here too
since it explains *why* this domain's real operations are shaped the way
they are, independent of which package currently holds the socket code.

## SSH port: threaded through via the gateway's ``extra`` escape hatch

The vendor-agnostic ``DeviceCredentials`` contract in ``wyfy_device_gateway``
has a single ``port`` field (used for the RouterOS API port, default 8728)
-- it has no dedicated SSH-port field, since not every vendor even has a
second port/transport the way MikroTik's SSH+SFTP file-transfer path does.
This domain's own ``DeviceCredentials.ssh_port`` (default 22, historically
configurable per-router) is threaded through via
``extra={"ssh_port": str(credentials.ssh_port)}`` -- exactly the escape
hatch ``DeviceCredentials.extra``'s own docstring in the gateway package
describes it as being for. Omitting this would silently drop a configured
non-default SSH port back to the gateway's own hardcoded default (22),
which would be a real, if narrow, regression for any router actually
configured with a non-standard SSH port.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.contract import DeviceInterfaceCounters, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    ProvisionDeviceConnectionError,
    ProvisionDeviceOperationError,
    UnsupportedDeviceVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_SSH_PORT = 22
_DEFAULT_TIMEOUT_SECONDS = 10


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
    """One health poll's result.

    ``interfaces`` carries the device's own per-interface byte counters
    when the adapter read them, and ``None`` when it did not. The
    gateway's ``DeviceInterfaceCounters`` is reused verbatim rather than
    restated here: a parallel dataclass with the same five fields is a
    drift waiting to happen, and this wrapper's entire job is to not lose
    fields on the way through.
    """

    healthy: bool
    cpu_load_percent: float | None
    free_memory_bytes: int | None
    uptime_seconds: int | None
    detail: str | None = None
    interfaces: tuple[DeviceInterfaceCounters, ...] | None = None


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
    Provisioning Engine. See module docstring for the "now delegates to
    wyfy-device-gateway" write-up. A new vendor is exactly: implement this
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
    """See module docstring for the full "now delegates to
    wyfy-device-gateway" write-up."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: DeviceCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
            extra={"ssh_port": str(credentials.ssh_port)},
        )

    async def discover(self, credentials: DeviceCredentials) -> DeviceDiscoveryResult:
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).discover(creds)
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("discover", exc.detail) from exc
        return DeviceDiscoveryResult(
            vendor=str(result.vendor),
            model=result.model,
            serial_number=result.serial_number,
            firmware_version=result.firmware_version,
            cpu_load_percent=result.cpu_load_percent,
            free_memory_bytes=result.free_memory_bytes,
            total_memory_bytes=result.total_memory_bytes,
            uptime_seconds=result.uptime_seconds,
            interfaces=list(result.interfaces),
            mac_address=result.mac_address,
        )

    async def push_config(
        self, credentials: DeviceCredentials, *, config_content: str
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).push_config(
                creds, config_content=config_content
            )
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("push_config", exc.detail) from exc

    async def verify_config(
        self, credentials: DeviceCredentials, *, expected_content: str
    ) -> bool:
        """Reads the config file back via SFTP and compares its SHA-256
        against ``expected_content`` -- a real, exact-content check, not a
        best-effort heuristic. See
        ``wyfy_device_gateway.mikrotik_adapter.MikroTikAdapter
        .verify_config``."""
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).verify_config(
                creds, expected_content=expected_content
            )
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("verify_config", exc.detail) from exc

    async def health_check(self, credentials: DeviceCredentials) -> DeviceHealthResult:
        """See module docstring's "the one genuinely subtle behavior in
        this domain" section: the gateway's own ``health_check`` already
        catches a *connection* failure internally and returns a graceful
        ``healthy=False`` result, so only a post-connection *operation*
        failure (a plain ``MikroTikDeviceError``, not the
        ``MikroTikConnectionError`` subclass) can ever escape the call
        below -- and that must propagate as a real
        ``ProvisionDeviceOperationError``, exactly like the original
        ``provisioning_engine/device_adapters.py::health_check`` never
        caught a post-connection failure either."""
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).health_check(creds)
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("health_check", exc.detail) from exc
        return DeviceHealthResult(
            healthy=result.healthy,
            cpu_load_percent=result.cpu_load_percent,
            free_memory_bytes=result.free_memory_bytes,
            uptime_seconds=result.uptime_seconds,
            detail=result.detail,
            interfaces=result.interfaces,
        )

    async def backup(self, credentials: DeviceCredentials) -> bytes:
        creds = self._gateway_credentials(credentials)
        try:
            return await get_adapter(DeviceVendor.MIKROTIK).backup(creds)
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("backup", exc.detail) from exc

    async def restore(
        self, credentials: DeviceCredentials, *, backup_content: bytes
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).restore(
                creds, backup_content=backup_content
            )
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("restore", exc.detail) from exc

    async def upload_file(
        self, credentials: DeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        creds = self._gateway_credentials(credentials)
        try:
            await get_adapter(DeviceVendor.MIKROTIK).upload_file(
                creds, filename=filename, content=content
            )
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        except MikroTikDeviceError as exc:
            raise ProvisionDeviceOperationError("upload_file", exc.detail) from exc

    async def execute_raw_command(
        self, credentials: DeviceCredentials, *, command: str
    ) -> RawCommandResult:
        creds = self._gateway_credentials(credentials)
        try:
            result = await get_adapter(DeviceVendor.MIKROTIK).execute_raw_command(
                creds, command=command
            )
        except MikroTikConnectionError as exc:
            raise ProvisionDeviceConnectionError(credentials.host, exc.detail) from exc
        return RawCommandResult(
            command=result.command,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_status=result.exit_status,
        )


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
    "DeviceInterfaceCounters",
    "RawCommandResult",
    "BaseProvisionAdapter",
    "MikroTikProvisionAdapter",
    "get_device_adapter",
    "list_supported_device_vendors",
]

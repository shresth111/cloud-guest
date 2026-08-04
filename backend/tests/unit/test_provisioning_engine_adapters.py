"""Unit tests for the Provisioning Engine's real device I/O adapter layer
(``app.domains.provisioning_engine.device_adapters``).

Per the ``wyfy-device-gateway`` migration (see that module's own "now
delegates to wyfy-device-gateway" docstring section), the real RouterOS
API/SSH transport logic and its command-construction/response-parsing now
live in ``wyfy_device_gateway.mikrotik_adapter`` -- and are covered by that
package's own test suite (``wyfy-device-gateway/tests/
test_mikrotik_provisioning_engine.py``), which this file does not
duplicate. What remains a genuine backend-owned concern, and what this
file actually tests:

* the registry (``get_device_adapter``/``list_supported_device_vendors``);
* ``MikroTikProvisionAdapter``'s own delegation logic -- that it maps this
  domain's ``DeviceCredentials`` to the gateway's vendor-agnostic
  ``DeviceCredentials`` correctly (including threading ``ssh_port`` through
  the gateway's ``extra`` escape hatch -- a real, easy-to-silently-drop
  detail since the gateway's own contract has no dedicated SSH-port
  field), calls the right gateway method with the right arguments, and
  translates the gateway's ``MikroTikConnectionError``/``MikroTikDeviceError``
  back into this domain's own ``ProvisionDeviceConnectionError``/
  ``ProvisionDeviceOperationError`` pair;
* ``health_check``'s one genuinely subtle real behavior: a post-connection
  operation failure (plain ``MikroTikDeviceError``) must propagate as a
  real exception, never get silently folded into a graceful
  ``healthy=False`` result the way a *connection* failure is (that
  graceful-degradation behavior itself now lives inside the gateway's own
  ``health_check`` and is tested there);
* one real, bounded, guaranteed-unreachable-host negative case (a genuine
  TEST-NET-1 connection attempt, never mocked) -- confirming the full,
  real delegation path still produces an honest
  ``ProvisionDeviceConnectionError``, never a fabricated success, end to
  end through the gateway.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import pytest
from wyfy_device_gateway.contract import (
    DeviceCredentials as GatewayDeviceCredentials,
)
from wyfy_device_gateway.contract import (
    DeviceDiscoveryResult as GatewayDeviceDiscoveryResult,
)
from wyfy_device_gateway.contract import (
    DeviceHealthResult as GatewayDeviceHealthResult,
)
from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.contract import RawCommandResult as GatewayRawCommandResult
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)

from app.domains.provisioning_engine.device_adapters import (
    DeviceCredentials,
    MikroTikProvisionAdapter,
    get_device_adapter,
    list_supported_device_vendors,
)
from app.domains.provisioning_engine.exceptions import (
    ProvisionDeviceConnectionError,
    ProvisionDeviceOperationError,
    UnsupportedDeviceVendorError,
)

CREDENTIALS = DeviceCredentials(host="10.0.0.1", username="admin", password="secret")

# ============================================================================
# Registry
# ============================================================================


class TestDeviceAdapterRegistry:
    def test_mikrotik_is_registered(self) -> None:
        adapter = get_device_adapter("mikrotik")
        assert isinstance(adapter, MikroTikProvisionAdapter)
        assert adapter.vendor == "mikrotik"

    def test_unknown_vendor_raises(self) -> None:
        with pytest.raises(UnsupportedDeviceVendorError):
            get_device_adapter("opnsense")

    def test_list_supported_device_vendors(self) -> None:
        assert list_supported_device_vendors() == ["mikrotik"]


# ============================================================================
# Fake gateway adapter -- stands in for
# wyfy_device_gateway.registry.get_adapter(DeviceVendor.MIKROTIK)
# ============================================================================


class FakeGatewayAdapter:
    """Records the gateway ``DeviceCredentials`` each method was called
    with (so tests can assert the mapping/``ssh_port``-via-``extra``
    plumbing is correct) and either returns a pre-seeded result or raises a
    pre-seeded exception -- never opens a real socket."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, GatewayDeviceCredentials, dict[str, object]]] = []
        self.raise_error: Exception | None = None
        self.discover_result: GatewayDeviceDiscoveryResult | None = None
        self.verify_config_result: bool = True
        self.health_check_result: GatewayDeviceHealthResult | None = None
        self.backup_result: bytes = b""
        self.execute_raw_command_result: GatewayRawCommandResult | None = None

    def _record(
        self, method: str, creds: GatewayDeviceCredentials, **kwargs: object
    ) -> None:
        self.calls.append((method, creds, kwargs))
        if self.raise_error is not None:
            raise self.raise_error

    async def discover(
        self, creds: GatewayDeviceCredentials
    ) -> GatewayDeviceDiscoveryResult:
        self._record("discover", creds)
        assert self.discover_result is not None
        return self.discover_result

    async def push_config(
        self, creds: GatewayDeviceCredentials, *, config_content: str
    ) -> None:
        self._record("push_config", creds, config_content=config_content)

    async def verify_config(
        self, creds: GatewayDeviceCredentials, *, expected_content: str
    ) -> bool:
        self._record("verify_config", creds, expected_content=expected_content)
        return self.verify_config_result

    async def health_check(
        self, creds: GatewayDeviceCredentials
    ) -> GatewayDeviceHealthResult:
        self._record("health_check", creds)
        assert self.health_check_result is not None
        return self.health_check_result

    async def backup(self, creds: GatewayDeviceCredentials) -> bytes:
        self._record("backup", creds)
        return self.backup_result

    async def restore(
        self, creds: GatewayDeviceCredentials, *, backup_content: bytes
    ) -> None:
        self._record("restore", creds, backup_content=backup_content)

    async def upload_file(
        self, creds: GatewayDeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        self._record("upload_file", creds, filename=filename, content=content)

    async def execute_raw_command(
        self, creds: GatewayDeviceCredentials, *, command: str
    ) -> GatewayRawCommandResult:
        self._record("execute_raw_command", creds, command=command)
        assert self.execute_raw_command_result is not None
        return self.execute_raw_command_result


@pytest.fixture
def fake_gateway_adapter(monkeypatch: pytest.MonkeyPatch) -> FakeGatewayAdapter:
    fake = FakeGatewayAdapter()
    monkeypatch.setattr(
        "app.domains.provisioning_engine.device_adapters.get_adapter",
        lambda vendor: fake,
    )
    return fake


# ============================================================================
# Credentials mapping (host/username/secret/port/timeout + ssh_port-via-extra)
# ============================================================================


class TestCredentialsMapping:
    async def test_maps_fields_and_threads_ssh_port_through_extra(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.discover_result = GatewayDeviceDiscoveryResult(
            vendor=DeviceVendor.MIKROTIK,
            model=None,
            serial_number=None,
            firmware_version=None,
            cpu_load_percent=None,
            free_memory_bytes=None,
            total_memory_bytes=None,
            uptime_seconds=None,
        )
        credentials = DeviceCredentials(
            host="192.168.1.1",
            username="admin",
            password="hunter2",
            api_port=8729,
            ssh_port=2222,
            timeout_seconds=15,
        )
        await MikroTikProvisionAdapter().discover(credentials)

        assert len(fake_gateway_adapter.calls) == 1
        _, creds, _ = fake_gateway_adapter.calls[0]
        assert creds.vendor == DeviceVendor.MIKROTIK
        assert creds.host == "192.168.1.1"
        assert creds.username == "admin"
        assert creds.secret == "hunter2"
        assert creds.port == 8729
        assert creds.timeout_seconds == 15
        assert creds.extra == {"ssh_port": "2222"}


# ============================================================================
# discover()
# ============================================================================


class TestDiscover:
    async def test_maps_gateway_result_shape(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.discover_result = GatewayDeviceDiscoveryResult(
            vendor=DeviceVendor.MIKROTIK,
            model="RB4011",
            serial_number="ABC123",
            firmware_version="7.14",
            cpu_load_percent=5.0,
            free_memory_bytes=104857600,
            total_memory_bytes=268435456,
            uptime_seconds=93845,
            interfaces=["ether1", "ether2"],
            mac_address="AA:BB:CC:DD:EE:FF",
        )
        result = await MikroTikProvisionAdapter().discover(CREDENTIALS)

        assert result.vendor == "mikrotik"
        assert result.model == "RB4011"
        assert result.serial_number == "ABC123"
        assert result.firmware_version == "7.14"
        assert result.cpu_load_percent == 5.0
        assert result.free_memory_bytes == 104857600
        assert result.total_memory_bytes == 268435456
        assert result.uptime_seconds == 93845
        assert result.interfaces == ["ether1", "ether2"]
        assert result.mac_address == "AA:BB:CC:DD:EE:FF"

    async def test_connection_error_translated(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.raise_error = MikroTikConnectionError(
            "10.0.0.1", "connection refused"
        )
        with pytest.raises(ProvisionDeviceConnectionError):
            await MikroTikProvisionAdapter().discover(CREDENTIALS)

    async def test_device_error_translated_to_operation_error(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.raise_error = MikroTikDeviceError("10.0.0.1", "boom")
        with pytest.raises(ProvisionDeviceOperationError):
            await MikroTikProvisionAdapter().discover(CREDENTIALS)


# ============================================================================
# push_config() / verify_config()
# ============================================================================


class TestPushAndVerifyConfig:
    async def test_push_config_delegates(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        await MikroTikProvisionAdapter().push_config(
            CREDENTIALS, config_content="/ip address add ..."
        )
        method, _, kwargs = fake_gateway_adapter.calls[0]
        assert method == "push_config"
        assert kwargs["config_content"] == "/ip address add ..."

    async def test_push_config_operation_failure_translated(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.raise_error = MikroTikDeviceError("10.0.0.1", "bad script")
        with pytest.raises(ProvisionDeviceOperationError):
            await MikroTikProvisionAdapter().push_config(
                CREDENTIALS, config_content="x"
            )

    async def test_verify_config_matched(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.verify_config_result = True
        matched = await MikroTikProvisionAdapter().verify_config(
            CREDENTIALS, expected_content="/ip address add ..."
        )
        assert matched is True

    async def test_verify_config_mismatch(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.verify_config_result = False
        matched = await MikroTikProvisionAdapter().verify_config(
            CREDENTIALS, expected_content="different"
        )
        assert matched is False

    async def test_upload_file_connection_failure_translated(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.raise_error = MikroTikConnectionError(
            "10.0.0.1", "auth failed"
        )
        with pytest.raises(ProvisionDeviceConnectionError):
            await MikroTikProvisionAdapter().upload_file(
                CREDENTIALS, filename="x.rsc", content=b"content"
            )


# ============================================================================
# health_check() -- the one genuinely subtle real behavior
# ============================================================================


class TestHealthCheck:
    async def test_success_maps_result(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.health_check_result = GatewayDeviceHealthResult(
            healthy=True,
            cpu_load_percent=10.0,
            free_memory_bytes=5000,
            uptime_seconds=3600,
        )
        result = await MikroTikProvisionAdapter().health_check(CREDENTIALS)
        assert result.healthy is True
        assert result.cpu_load_percent == 10.0
        assert result.free_memory_bytes == 5000
        assert result.uptime_seconds == 3600

    async def test_gateway_already_reports_graceful_unhealthy_on_connection_failure(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        """The gateway's own ``health_check`` catches a connection failure
        internally -- by the time it reaches this domain's adapter, it is
        already a normal, non-exceptional ``DeviceHealthResult(healthy=
        False, ...)``, never a raised ``MikroTikConnectionError``. This
        test documents that this domain's own ``health_check`` has no
        ``MikroTikConnectionError`` handler at all -- there is nothing to
        catch, by design."""
        fake_gateway_adapter.health_check_result = GatewayDeviceHealthResult(
            healthy=False,
            cpu_load_percent=None,
            free_memory_bytes=None,
            uptime_seconds=None,
            detail="Could not connect to device at '10.0.0.1': timed out",
        )
        result = await MikroTikProvisionAdapter().health_check(CREDENTIALS)
        assert result.healthy is False
        assert result.detail is not None

    async def test_operation_failure_propagates_as_real_exception(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        """A post-connection operation failure is NOT caught -- it must
        propagate as a real ``ProvisionDeviceOperationError``, exactly like
        the original ``provisioning_engine/device_adapters.py::health_check``
        never caught one either."""
        fake_gateway_adapter.raise_error = MikroTikDeviceError(
            "10.0.0.1", "command rejected"
        )
        with pytest.raises(ProvisionDeviceOperationError):
            await MikroTikProvisionAdapter().health_check(CREDENTIALS)


# ============================================================================
# backup() / restore()
# ============================================================================


class TestBackupRestore:
    async def test_backup_returns_bytes(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.backup_result = b"\x00binarybackupbytes"
        content = await MikroTikProvisionAdapter().backup(CREDENTIALS)
        assert content == b"\x00binarybackupbytes"

    async def test_restore_delegates(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        await MikroTikProvisionAdapter().restore(
            CREDENTIALS, backup_content=b"restored-bytes"
        )
        method, _, kwargs = fake_gateway_adapter.calls[0]
        assert method == "restore"
        assert kwargs["backup_content"] == b"restored-bytes"

    async def test_backup_connection_failure_translated(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.raise_error = MikroTikConnectionError(
            "10.0.0.1", "unreachable"
        )
        with pytest.raises(ProvisionDeviceConnectionError):
            await MikroTikProvisionAdapter().backup(CREDENTIALS)


# ============================================================================
# execute_raw_command() -- never raises on non-zero exit status
# ============================================================================


class TestExecuteRawCommand:
    async def test_returns_real_unfiltered_result_even_on_nonzero_exit(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.execute_raw_command_result = GatewayRawCommandResult(
            command="/interface print", stdout="", stderr="oops", exit_status=1
        )
        result = await MikroTikProvisionAdapter().execute_raw_command(
            CREDENTIALS, command="/interface print"
        )
        assert result.command == "/interface print"
        assert result.exit_status == 1
        assert result.stderr == "oops"

    async def test_connection_failure_translated(
        self, fake_gateway_adapter: FakeGatewayAdapter
    ) -> None:
        fake_gateway_adapter.raise_error = MikroTikConnectionError(
            "10.0.0.1", "auth failed"
        )
        with pytest.raises(ProvisionDeviceConnectionError):
            await MikroTikProvisionAdapter().execute_raw_command(
                CREDENTIALS, command="/interface print"
            )


# ============================================================================
# Real, bounded, guaranteed-unreachable-host negative case
# ============================================================================


class TestRealUnreachableHostNeverFabricatesSuccess:
    async def test_connecting_to_test_net_1_raises_honest_connection_error(
        self,
    ) -> None:
        """``192.0.2.1`` is a TEST-NET-1 address (RFC 5737) -- reserved for
        documentation/testing, guaranteed never to route anywhere. A real
        connection attempt against it, with a short timeout, must raise a
        real ``ProvisionDeviceConnectionError`` end to end through the real
        (unmocked) delegation to ``wyfy_device_gateway`` -- never a
        fabricated success. This is the one test in this file that opens a
        real (and always-failing) socket."""
        adapter = MikroTikProvisionAdapter()
        credentials = DeviceCredentials(
            host="192.0.2.1",
            username="admin",
            password="secret",
            timeout_seconds=1,
        )
        with pytest.raises(ProvisionDeviceConnectionError):
            await adapter.discover(credentials)

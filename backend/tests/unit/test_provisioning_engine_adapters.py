"""Unit tests for the Provisioning Engine's real device I/O adapter layer
(``app.domains.provisioning_engine.device_adapters``).

Per that module's own "real client code, untested end-to-end here" scope
note, ``MikroTikProvisionAdapter``'s command-construction and response-
parsing logic is exercised here via hand-rolled fake ``librouteros``/
``asyncssh`` transports (monkeypatching ``librouteros.connect``/
``asyncssh.connect``) -- never a real socket. This mirrors how
``app.domains.guest`` tests its FreeRADIUS ``rlm_rest`` integration and how
``app.domains.router_agent``'s own HTTP surface is tested, both without a
live counterpart process. Also covers a genuine, real-network negative
case: a connection attempt to a guaranteed-unreachable TEST-NET-1 address
(``192.0.2.1``), which must raise a real ``ProvisionDeviceConnectionError``,
never a fabricated success -- this is the one test in this suite that
actually opens a real (failing) socket, bounded by a 1-second timeout.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import asyncssh
import librouteros
import pytest
from librouteros.exceptions import LibRouterosError

from app.domains.provisioning_engine.device_adapters import (
    DeviceCredentials,
    MikroTikProvisionAdapter,
    _as_float,
    _as_int,
    _parse_routeros_uptime,
    get_device_adapter,
    list_supported_device_vendors,
)
from app.domains.provisioning_engine.exceptions import (
    ProvisionDeviceConnectionError,
    ProvisionDeviceOperationError,
    UnsupportedDeviceVendorError,
)

# ============================================================================
# Module-level parsing helpers
# ============================================================================


class TestParseRouterosUptime:
    def test_parses_full_format(self) -> None:
        assert _parse_routeros_uptime("3w2d4h5m6s") == (
            3 * 604800 + 2 * 86400 + 4 * 3600 + 5 * 60 + 6
        )

    def test_parses_partial_format(self) -> None:
        assert _parse_routeros_uptime("4h5m6s") == 4 * 3600 + 5 * 60 + 6

    def test_parses_seconds_only(self) -> None:
        assert _parse_routeros_uptime("42s") == 42

    def test_none_input_returns_none(self) -> None:
        assert _parse_routeros_uptime(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert _parse_routeros_uptime("") is None

    def test_unrecognized_unit_returns_none(self) -> None:
        assert _parse_routeros_uptime("3x") is None


class TestAsFloatAsInt:
    def test_as_float_plain(self) -> None:
        assert _as_float("12.5") == 12.5

    def test_as_float_strips_percent(self) -> None:
        assert _as_float("42%") == 42.0

    def test_as_float_none(self) -> None:
        assert _as_float(None) is None

    def test_as_float_invalid_returns_none(self) -> None:
        assert _as_float("not-a-number") is None

    def test_as_int_plain(self) -> None:
        assert _as_int("1024") == 1024

    def test_as_int_none(self) -> None:
        assert _as_int(None) is None

    def test_as_int_invalid_returns_none(self) -> None:
        assert _as_int("not-a-number") is None


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
# Fake librouteros / asyncssh transports
# ============================================================================


class FakeRouterosApi:
    """Stands in for the callable object ``librouteros.connect()`` returns.
    Each RouterOS "path" (e.g. ``/system/resource/print``) is pre-seeded
    with the rows it should yield when called."""

    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.closed = False

    def __call__(self, path: str) -> list[dict[str, object]]:
        if path not in self.responses:
            raise LibRouterosError(f"no fake response seeded for {path}")
        return self.responses[path]

    def close(self) -> None:
        self.closed = True


class FakeRemoteFile:
    def __init__(self, files: dict[str, bytes], filename: str, mode: str) -> None:
        self._files = files
        self._filename = filename
        self._mode = mode

    async def __aenter__(self) -> FakeRemoteFile:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def read(self) -> bytes:
        return self._files[self._filename]

    async def write(self, content: bytes) -> None:
        self._files[self._filename] = content


class FakeSftpClient:
    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    async def __aenter__(self) -> FakeSftpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    def open(self, filename: str, mode: str) -> FakeRemoteFile:
        return FakeRemoteFile(self._files, filename, mode)


class FakeSshRunResult:
    def __init__(self, exit_status: int = 0, stderr: str = "") -> None:
        self.exit_status = exit_status
        self.stderr = stderr


class FakeSshConnection:
    def __init__(
        self, files: dict[str, bytes], run_result: FakeSshRunResult | None = None
    ) -> None:
        self._files = files
        self.run_result = run_result or FakeSshRunResult()
        self.commands_run: list[str] = []

    async def __aenter__(self) -> FakeSshConnection:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def run(self, command: str, check: bool = False) -> FakeSshRunResult:
        self.commands_run.append(command)
        return self.run_result

    def start_sftp_client(self) -> FakeSftpClient:
        return FakeSftpClient(self._files)


class RaisingConnect:
    """A fake ``connect`` callable that always raises -- simulates a real
    unreachable host / auth failure without opening any socket."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def __call__(self, *args: object, **kwargs: object) -> None:
        raise self.exc


CREDENTIALS = DeviceCredentials(host="10.0.0.1", username="admin", password="secret")


# ============================================================================
# discover()
# ============================================================================


class TestDiscover:
    async def test_parses_real_response_shape(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi(
            {
                "/system/resource/print": [
                    {
                        "version": "7.14",
                        "cpu-load": "5",
                        "free-memory": "104857600",
                        "total-memory": "268435456",
                        "uptime": "1w2d3h4m5s",
                    }
                ],
                "/system/routerboard/print": [
                    {"model": "RB4011", "serial-number": "ABC123"}
                ],
                "/interface/print": [
                    {"name": "ether1", "mac-address": "AA:BB:CC:DD:EE:FF"},
                    {"name": "ether2", "mac-address": "11:22:33:44:55:66"},
                ],
            }
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)

        adapter = MikroTikProvisionAdapter()
        result = await adapter.discover(CREDENTIALS)

        assert result.vendor == "mikrotik"
        assert result.model == "RB4011"
        assert result.serial_number == "ABC123"
        assert result.firmware_version == "7.14"
        assert result.cpu_load_percent == 5.0
        assert result.free_memory_bytes == 104857600
        assert result.total_memory_bytes == 268435456
        assert result.uptime_seconds == 1 * 604800 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5
        assert result.interfaces == ["ether1", "ether2"]
        assert result.mac_address == "AA:BB:CC:DD:EE:FF"
        assert api.closed is True

    async def test_connection_failure_raises_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            librouteros, "connect", RaisingConnect(OSError("connection refused"))
        )
        adapter = MikroTikProvisionAdapter()
        with pytest.raises(ProvisionDeviceConnectionError):
            await adapter.discover(CREDENTIALS)

    async def test_command_failure_raises_operation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An empty response map means every path lookup raises LibRouterosError.
        api = FakeRouterosApi({})
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikProvisionAdapter()
        with pytest.raises(ProvisionDeviceOperationError):
            await adapter.discover(CREDENTIALS)
        assert api.closed is True


# ============================================================================
# health_check()
# ============================================================================


class TestHealthCheck:
    async def test_success_reports_healthy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi(
            {
                "/system/resource/print": [
                    {"cpu-load": "10", "free-memory": "5000", "uptime": "1h"}
                ]
            }
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikProvisionAdapter()
        result = await adapter.health_check(CREDENTIALS)
        assert result.healthy is True
        assert result.cpu_load_percent == 10.0
        assert result.free_memory_bytes == 5000
        assert result.uptime_seconds == 3600

    async def test_connection_failure_reports_unhealthy_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            librouteros, "connect", RaisingConnect(OSError("timed out"))
        )
        adapter = MikroTikProvisionAdapter()
        result = await adapter.health_check(CREDENTIALS)
        assert result.healthy is False
        assert result.detail is not None


# ============================================================================
# push_config() / verify_config()
# ============================================================================


class TestPushAndVerifyConfig:
    async def test_push_then_verify_round_trips(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        files: dict[str, bytes] = {}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        adapter = MikroTikProvisionAdapter()
        await adapter.push_config(CREDENTIALS, config_content="/ip address add ...")
        assert files["cloudguest-config.rsc"] == b"/ip address add ..."
        assert any("/import" in c for c in conn.commands_run)

        matched = await adapter.verify_config(
            CREDENTIALS, expected_content="/ip address add ..."
        )
        assert matched is True

    async def test_verify_config_mismatch_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        files = {"cloudguest-config.rsc": b"actual content on device"}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        adapter = MikroTikProvisionAdapter()
        matched = await adapter.verify_config(
            CREDENTIALS, expected_content="different expected content"
        )
        assert matched is False

    async def test_push_config_run_command_failure_raises_operation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        files: dict[str, bytes] = {}
        conn = FakeSshConnection(
            files, run_result=FakeSshRunResult(exit_status=1, stderr="bad script")
        )
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        adapter = MikroTikProvisionAdapter()
        with pytest.raises(ProvisionDeviceOperationError):
            await adapter.push_config(CREDENTIALS, config_content="broken")

    async def test_upload_file_connection_failure_raises_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            asyncssh, "connect", RaisingConnect(asyncssh.Error(0, "auth failed"))
        )
        adapter = MikroTikProvisionAdapter()
        with pytest.raises(ProvisionDeviceConnectionError):
            await adapter.upload_file(CREDENTIALS, filename="x.rsc", content=b"content")


# ============================================================================
# backup() / restore()
# ============================================================================


class TestBackupRestore:
    async def test_backup_downloads_saved_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        files = {"cloudguest-backup.backup": b"\x00binarybackupbytes"}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        adapter = MikroTikProvisionAdapter()
        content = await adapter.backup(CREDENTIALS)
        assert content == b"\x00binarybackupbytes"
        assert any("/system/backup/save" in c for c in conn.commands_run)

    async def test_restore_uploads_then_loads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        files: dict[str, bytes] = {}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        adapter = MikroTikProvisionAdapter()
        await adapter.restore(CREDENTIALS, backup_content=b"restored-bytes")
        assert files["cloudguest-backup.backup"] == b"restored-bytes"
        assert any("/system/backup/load" in c for c in conn.commands_run)


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
        real ``ProvisionDeviceConnectionError`` -- never a fabricated
        success. This is the one test in this file that opens a real (and
        always-failing) socket."""
        adapter = MikroTikProvisionAdapter()
        credentials = DeviceCredentials(
            host="192.0.2.1",
            username="admin",
            password="secret",
            timeout_seconds=1,
        )
        with pytest.raises(ProvisionDeviceConnectionError):
            await adapter.discover(credentials)

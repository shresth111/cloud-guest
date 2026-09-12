"""Provisioning engine: discover/push_config/verify_config/health_check/
backup/restore/upload_file -- ported from
``provisioning_engine/device_adapters.py``. (``execute_raw_command`` moved
from SSH to the API in cloud-guest #176 and is covered by
``test_mikrotik_raw_console.py``.) Mirrors that module's own
test file's fake ``librouteros``/``asyncssh`` transports (hand-rolled,
never a real socket except this file's own bounded real-network negative
case)."""

from __future__ import annotations

import asyncssh
import librouteros
import pytest
from librouteros.exceptions import LibRouterosError

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikConnectionError,
    MikroTikDeviceError,
)

CREDENTIALS = DeviceCredentials(
    vendor=DeviceVendor.MIKROTIK, host="10.0.0.1", username="admin", secret="secret"
)


# ============================================================================
# Fake librouteros / asyncssh transports (mirrors cloud-guest-repo's own
# tests/unit/test_provisioning_engine_adapters.py fakes)
# ============================================================================


class FakeRouterosApi:
    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.closed = False

    def __call__(self, path: str) -> list[dict[str, object]]:
        if path not in self.responses:
            raise LibRouterosError(f"no fake response seeded for {path}")
        return self.responses[path]

    def path(self, *segments: str) -> list[dict[str, object]]:
        # health_check reads ``/interface`` through the menu API as well as
        # ``/system/resource/print`` through a one-shot command. Seeded the
        # same way, keyed by the joined path.
        return self("/" + "/".join(segments))

    def close(self) -> None:
        self.closed = True


class FakeRemoteFile:
    def __init__(self, files: dict[str, bytes], filename: str, mode: str) -> None:
        self._files = files
        self._filename = filename
        self._mode = mode

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def read(self) -> bytes:
        return self._files[self._filename]

    async def write(self, content: bytes) -> None:
        self._files[self._filename] = content


class FakeSftpClient:
    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    def open(self, filename: str, mode: str) -> FakeRemoteFile:
        return FakeRemoteFile(self._files, filename, mode)


class FakeSshRunResult:
    def __init__(self, exit_status: int = 0, stderr: str = "") -> None:
        self.exit_status = exit_status
        self.stderr = stderr
        self.stdout = ""


class FakeSshConnection:
    def __init__(self, files: dict[str, bytes], run_result=None) -> None:
        self._files = files
        self.run_result = run_result or FakeSshRunResult()
        self.commands_run: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def run(self, command: str, check: bool = False):
        self.commands_run.append(command)
        return self.run_result

    def start_sftp_client(self) -> FakeSftpClient:
        return FakeSftpClient(self._files)


class RaisingConnect:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def __call__(self, *args, **kwargs):
        raise self.exc


# ============================================================================
# discover()
# ============================================================================


class TestDiscover:
    async def test_parses_real_response_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
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

        result = await MikroTikAdapter().discover(CREDENTIALS)

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
        with pytest.raises(MikroTikConnectionError):
            await MikroTikAdapter().discover(CREDENTIALS)

    async def test_command_failure_raises_operation_error_not_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi({})
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        with pytest.raises(MikroTikDeviceError) as exc_info:
            await MikroTikAdapter().discover(CREDENTIALS)
        assert not isinstance(exc_info.value, MikroTikConnectionError)
        assert api.closed is True


# ============================================================================
# health_check() -- only a CONNECTION failure is caught gracefully
# ============================================================================


class TestHealthCheck:
    async def test_success_reports_healthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = FakeRouterosApi(
            {"/system/resource/print": [{"cpu-load": "10", "free-memory": "5000", "uptime": "1h"}]}
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        result = await MikroTikAdapter().health_check(CREDENTIALS)
        assert result.healthy is True
        assert result.cpu_load_percent == 10.0
        assert result.free_memory_bytes == 5000
        assert result.uptime_seconds == 3600

    async def test_connection_failure_reports_unhealthy_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(librouteros, "connect", RaisingConnect(OSError("timed out")))
        result = await MikroTikAdapter().health_check(CREDENTIALS)
        assert result.healthy is False
        assert result.detail is not None

    async def test_command_failure_propagates_not_caught(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real, ported behavior: unlike a connection failure, a
        post-connection command failure is NOT caught by health_check --
        it propagates as a real exception, exactly like the original
        ``provisioning_engine/device_adapters.py::health_check``."""
        api = FakeRouterosApi({})  # empty responses -> every path raises
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        with pytest.raises(MikroTikDeviceError) as exc_info:
            await MikroTikAdapter().health_check(CREDENTIALS)
        assert not isinstance(exc_info.value, MikroTikConnectionError)


# ============================================================================
# push_config() / verify_config()
# ============================================================================


class TestPushAndVerifyConfig:
    async def test_push_then_verify_round_trips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        files: dict[str, bytes] = {}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        adapter = MikroTikAdapter()
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

        matched = await MikroTikAdapter().verify_config(
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

        with pytest.raises(MikroTikDeviceError) as exc_info:
            await MikroTikAdapter().push_config(CREDENTIALS, config_content="broken")
        assert not isinstance(exc_info.value, MikroTikConnectionError)

    async def test_upload_file_connection_failure_raises_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            asyncssh, "connect", RaisingConnect(asyncssh.Error(0, "auth failed"))
        )
        with pytest.raises(MikroTikConnectionError):
            await MikroTikAdapter().upload_file(
                CREDENTIALS, filename="x.rsc", content=b"content"
            )


# ============================================================================
# backup() / restore()
# ============================================================================


class TestBackupRestore:
    async def test_backup_downloads_saved_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        files = {"cloudguest-backup.backup": b"\x00binarybackupbytes"}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        content = await MikroTikAdapter().backup(CREDENTIALS)
        assert content == b"\x00binarybackupbytes"
        assert any("/system/backup/save" in c for c in conn.commands_run)

    async def test_restore_uploads_then_loads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        files: dict[str, bytes] = {}
        conn = FakeSshConnection(files)
        monkeypatch.setattr(asyncssh, "connect", lambda *a, **kw: conn)

        await MikroTikAdapter().restore(CREDENTIALS, backup_content=b"restored-bytes")
        assert files["cloudguest-backup.backup"] == b"restored-bytes"
        assert any("/system/backup/load" in c for c in conn.commands_run)


# ============================================================================
# Real, bounded, guaranteed-unreachable-host negative case
# ============================================================================


class TestRealUnreachableHostNeverFabricatesSuccess:
    async def test_connecting_to_test_net_1_raises_honest_connection_error(self) -> None:
        credentials = DeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host="192.0.2.1",
            username="admin",
            secret="secret",
            timeout_seconds=1,
        )
        with pytest.raises(MikroTikConnectionError):
            await MikroTikAdapter().discover(credentials)

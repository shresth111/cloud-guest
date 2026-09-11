"""A router that goes quiet *mid-command* raises a bare socket error from
librouteros -- ``OSError`` (a recv ``TimeoutError`` included) or
``EOFError`` -- never a ``LibRouterosError``. On the ISP reads those used
to escape the adapter's ``MikroTikConnectionError``/``MikroTikDeviceError``
contract entirely; they must now arrive as a connection error. And a
``close()`` that fails on the broken socket must never mask the real
outcome. (wyfy-device-gateway#1, folded in when this vendored copy became
the canonical one.)"""

from __future__ import annotations

from typing import Any

import pytest
from librouteros.exceptions import LibRouterosError

from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikConnectionError


class _DeadSocketApi:
    """Connects fine, then every read or command dies with ``exc``; and
    ``close()`` fails too, as it does on a socket that is already gone."""

    def __init__(self, exc: BaseException, *, close_raises: bool = True) -> None:
        self._exc = exc
        self._close_raises = close_raises
        self.close_attempted = False

    def path(self, *segments: str) -> Any:
        raise self._exc

    def __call__(self, cmd: str, **kwargs: Any) -> Any:
        raise self._exc

    def close(self) -> None:
        self.close_attempted = True
        if self._close_raises:
            raise OSError("close on a dead socket")


class _HealthyReadBrokenCloseApi:
    def __init__(self, rows: dict[tuple[str, ...], list[dict[str, Any]]]) -> None:
        self._rows = rows

    def path(self, *segments: str) -> Any:
        return iter(self._rows.get(segments, []))

    def close(self) -> None:
        raise OSError("close on a dead socket")


_DEAD_SOCKET_ERRORS = [TimeoutError(), EOFError(), ConnectionResetError("reset by peer")]


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", _DEAD_SOCKET_ERRORS, ids=lambda e: type(e).__name__)
async def test_active_default_gateway_maps_dead_socket_to_connection_error(
    patch_connect, mikrotik_creds, exc
):
    api = _DeadSocketApi(exc)
    patch_connect(api)
    with pytest.raises(MikroTikConnectionError) as info:
        await MikroTikAdapter().get_active_default_gateway(mikrotik_creds)
    assert "read_active_default_route" in str(info.value)
    assert api.close_attempted


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", _DEAD_SOCKET_ERRORS, ids=lambda e: type(e).__name__)
async def test_pppoe_status_maps_dead_socket_to_connection_error(
    patch_connect, mikrotik_creds, exc
):
    patch_connect(_DeadSocketApi(exc))
    with pytest.raises(MikroTikConnectionError):
        await MikroTikAdapter().get_pppoe_interface_status(
            mikrotik_creds, interface_name="pppoe-out1"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", _DEAD_SOCKET_ERRORS, ids=lambda e: type(e).__name__)
async def test_traffic_counters_map_dead_socket_to_connection_error(
    patch_connect, mikrotik_creds, exc
):
    patch_connect(_DeadSocketApi(exc))
    with pytest.raises(MikroTikConnectionError):
        await MikroTikAdapter().get_interface_traffic_counters(
            mikrotik_creds, interface_name="ether1"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", _DEAD_SOCKET_ERRORS, ids=lambda e: type(e).__name__)
async def test_speed_test_maps_dead_socket_to_connection_error_despite_failed_cleanup(
    patch_connect, mikrotik_creds, exc
):
    """The fetch dies, the ``/file`` cleanup in its ``finally`` dies the same
    way, and ``close()`` dies too. The caller must still see the one real
    failure -- the fetch -- as a connection error, not whichever of the
    later errors happened to be raised last."""
    patch_connect(_DeadSocketApi(exc))
    with pytest.raises(MikroTikConnectionError) as info:
        await MikroTikAdapter().run_speed_test(
            mikrotik_creds, download_url="https://example.com/10MB.bin"
        )
    assert "run_speed_test" in str(info.value)


@pytest.mark.asyncio
async def test_timeout_message_is_not_empty(patch_connect, mikrotik_creds):
    """A bare ``TimeoutError``'s ``str()`` is empty; the error an operator
    reads must still say what happened."""
    patch_connect(_DeadSocketApi(TimeoutError()))
    with pytest.raises(MikroTikConnectionError) as info:
        await MikroTikAdapter().get_active_default_gateway(mikrotik_creds)
    detail = str(info.value).split("read_active_default_route:", 1)[1]
    assert detail.strip()


@pytest.mark.asyncio
async def test_failed_close_does_not_turn_a_good_read_into_a_failure(
    patch_connect, mikrotik_creds
):
    patch_connect(
        _HealthyReadBrokenCloseApi(
            {("interface",): [{"name": "ether1", "rx-byte": "100", "tx-byte": "200"}]}
        )
    )
    counters = await MikroTikAdapter().get_interface_traffic_counters(
        mikrotik_creds, interface_name="ether1"
    )
    assert counters == (100, 200)


class _FetchOkCleanupRejectedApi:
    """The download completes; RouterOS then refuses the ``/file`` read
    used to delete the temp file."""

    def path(self, *segments: str) -> Any:
        raise LibRouterosError("no such command")

    def __call__(self, cmd: str, **kwargs: Any) -> Any:
        return iter([{"status": "finished", "downloaded": "10240", "duration": "2s"}])

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_speed_test_result_survives_a_rejected_cleanup(patch_connect, mikrotik_creds):
    """The cleanup's warning used to pass ``filename`` in ``extra``, a
    reserved LogRecord attribute, so logging raised KeyError -- and a
    finished speed test whose temp-file removal was refused came back as a
    KeyError instead of its result."""
    patch_connect(_FetchOkCleanupRejectedApi())
    result = await MikroTikAdapter().run_speed_test(
        mikrotik_creds, download_url="https://example.com/10MB.bin"
    )
    assert result.downloaded_bytes == 10240 * 1024
    assert result.duration_seconds == 2.0

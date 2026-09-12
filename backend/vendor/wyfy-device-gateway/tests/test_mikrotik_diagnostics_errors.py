"""``ping``/``traceroute`` must translate a socket read timeout, not leak it.

The bug these pin: ``librouteros.connect`` passes ``timeout`` to
``socket.create_connection``, which makes it the timeout on every
subsequent ``recv`` as well as on the connect itself, and librouteros'
own ``SocketTransport.read`` calls ``sock.recv`` with no exception
translation whatsoever. So a router that accepts the connection and then
stops replying -- a flaky tunnel, a saturated uplink, an unresponsive
traceroute hop -- raises a bare ``TimeoutError``.

``TimeoutError`` is a subclass of ``OSError`` and is **not** a
``LibRouterosError``, so the ``except LibRouterosError`` these two methods
used to carry never matched it. It escaped this adapter, then the
consuming domain's own adapter (which catches only
``MikroTikConnectionError``/``MikroTikDeviceError``), then that domain's
service (which catches only its two device-error types), and surfaced to
the caller as an HTTP 500 with no record written at all -- so the single
failure mode a diagnostics screen most needs to report honestly was the
one failure that left no trace anywhere.
"""

from __future__ import annotations

from typing import Any

import pytest
from librouteros.exceptions import TrapError
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikConnectionError,
    MikroTikDeviceError,
)


class _Api:
    """Callable stand-in for a ``librouteros`` connection.

    The real object is called as ``api("/tool/ping", address=...)`` and
    returns a generator whose *iteration* performs the socket reads, so
    the failure is raised from iteration rather than from the call --
    faithful to where the real timeout actually happens.
    """

    def __init__(self, exception: BaseException) -> None:
        self._exception = exception
        self.closed = False

    def __call__(self, *_args: Any, **_kwargs: Any):
        def _generator():
            raise self._exception
            yield  # pragma: no cover -- unreachable, makes this a generator

        return _generator()

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    "raised",
    [
        # The real shape: socket.timeout IS TimeoutError in modern Python.
        TimeoutError(),
        # A tunnel dropping mid-command rather than stalling.
        ConnectionResetError("connection reset by peer"),
    ],
)
async def test_ping_translates_a_socket_error_into_a_device_error(
    mikrotik_creds, patch_connect, raised: BaseException
) -> None:
    api = _Api(raised)
    patch_connect(api)
    with pytest.raises(MikroTikDeviceError) as exc:
        await MikroTikAdapter().ping(
            mikrotik_creds, target="1.1.1.1", count=5, timeout_seconds=10
        )
    # Not the connection subclass: the connection was opened, then the
    # command stalled -- a genuinely different thing to report.
    assert not isinstance(exc.value, MikroTikConnectionError)
    assert api.closed, "the api connection must still be closed on failure"


async def test_a_bare_timeout_still_carries_a_readable_detail(
    mikrotik_creds, patch_connect
) -> None:
    """``str(TimeoutError())`` is empty, which is exactly why
    ``_describe_exception`` exists -- without it an operator saw a message
    that ended after its own colon."""
    patch_connect(_Api(TimeoutError()))
    with pytest.raises(MikroTikDeviceError) as exc:
        await MikroTikAdapter().ping(
            mikrotik_creds, target="1.1.1.1", count=5, timeout_seconds=10
        )
    assert exc.value.detail.strip()
    assert not exc.value.detail.rstrip().endswith(":")


async def test_traceroute_translates_a_socket_error_too(
    mikrotik_creds, patch_connect
) -> None:
    """A traceroute is the likelier of the two to stall: an unresponsive
    hop is a normal thing for it to meet."""
    api = _Api(TimeoutError())
    patch_connect(api)
    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().traceroute(
            mikrotik_creds, target="1.1.1.1", max_hops=15, timeout_seconds=15
        )
    assert api.closed


async def test_a_routeros_trap_is_still_a_device_error(
    mikrotik_creds, patch_connect
) -> None:
    """Regression: widening the except clause must not change how a real
    RouterOS ``!trap`` (an unresolvable target, a refused command) is
    reported -- that path already worked and is what a normal 'target
    unreachable' failure travels down."""
    patch_connect(_Api(TrapError("could not resolve host")))
    with pytest.raises(MikroTikDeviceError) as exc:
        await MikroTikAdapter().ping(
            mikrotik_creds, target="nope.invalid", count=5, timeout_seconds=10
        )
    assert "could not resolve host" in exc.value.detail

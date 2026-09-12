"""``run_speed_test`` -- a real, on-demand RouterOS ``/tool/fetch`` download
used to measure genuine WAN download throughput (PRD-adjacent: this method
was added for the Wyfy Guest "Run Speed Test" feature, not part of the
original PRD section 2.1 audit, but ported into the same real-command /
real-parsing / fake-transport-only-in-tests posture as every other method in
this module).

Real-device confirmation this test suite's expectations are modeled on
(performed against the real test org's real MikroTik hEX lite router over
its real Airtel WAN link, RouterOS 7.16.2, never against a live device in
this sandbox itself):

* ``/tool/bandwidth-test`` is not usable against the general internet and
  isn't even a real REST endpoint on this router/version -- confirmed dead
  end, not assumed.
* ``/tool/fetch`` genuinely downloads a real file and reports real
  cumulative ``downloaded``/``total`` (KiB) and ``duration`` fields,
  finishing with ``status: "finished"``. A real 10MB fetch against
  ``https://speed.cloudflare.com/__down?bytes=10000000`` took 6 real
  seconds and transferred 9765 real KiB (~13.3 Mbps) -- the shape this
  suite's fake replies mirror.
* ``duration`` only ever increments in whole seconds on this router/
  version -- even a real 200KB fetch (well under one second of real
  transfer time) still reported ``duration: "1s"``, never a sub-second
  value.
* A real ``TrapError`` (e.g. DNS resolution failure) is raised by
  ``librouteros`` mid-command, not returned as a "failed" status row --
  the fake transport's ``raise_on_command`` mirrors this.
"""

from __future__ import annotations

import uuid

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import SpeedTestResult
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError

_FIXED_UUID = uuid.UUID("12345678-1234-5678-1234-567812345678")
_TEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"


def _patch_uuid(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pins the adapter's random filename suffix so tests can assert on the
    exact ``/file remove`` call. Returns the resulting filename."""
    monkeypatch.setattr(
        "wyfy_device_gateway.mikrotik_adapter.uuid.uuid4", lambda: _FIXED_UUID
    )
    return f"wyfy-speedtest-{_FIXED_UUID.hex[:10]}.tmp"


@pytest.mark.asyncio
async def test_run_speed_test_computes_real_mbps_from_last_row(
    monkeypatch, patch_connect, mikrotik_creds
):
    filename = _patch_uuid(monkeypatch)
    api = FakeRouterOSApi(
        command_replies={
            "/tool/fetch": [
                {"status": "connecting"},
                {
                    "status": "downloading",
                    "downloaded": "824",
                    "total": "9765",
                    "duration": "1s",
                },
                {
                    "status": "finished",
                    "downloaded": "9765",
                    "total": "9765",
                    "duration": "6s",
                },
            ],
        },
        menus={("file",): [{".id": "*1", "name": filename, "size": "10000000"}]},
    )
    patch_connect(api)

    result = await MikroTikAdapter().run_speed_test(
        mikrotik_creds, download_url=_TEST_URL
    )

    assert isinstance(result, SpeedTestResult)
    assert result.downloaded_bytes == 9765 * 1024
    assert result.duration_seconds == 6.0
    assert result.download_mbps == round((9765 * 1024 * 8) / 6 / 1_000_000, 2)
    assert result.test_url == _TEST_URL
    # Real cleanup: the downloaded file is removed from the router's own
    # flash storage afterward, regardless of the low-flash-capacity concern
    # this exists to address.
    assert api.remove_calls == [(("file",), ("*1",))]
    assert api.closed is True


@pytest.mark.asyncio
async def test_run_speed_test_leaves_no_file_when_nothing_matches(
    monkeypatch, patch_connect, mikrotik_creds
):
    """No stray file left behind even if, somehow, the expected filename
    never shows up on the router's own file menu."""
    _patch_uuid(monkeypatch)
    api = FakeRouterOSApi(
        command_replies={
            "/tool/fetch": [
                {"status": "finished", "downloaded": "500", "total": "500", "duration": "2s"},
            ],
        },
    )
    patch_connect(api)

    result = await MikroTikAdapter().run_speed_test(
        mikrotik_creds, download_url=_TEST_URL
    )

    assert result.downloaded_bytes == 500 * 1024
    assert api.remove_calls == []


@pytest.mark.asyncio
async def test_run_speed_test_raises_on_real_fetch_failure(
    monkeypatch, patch_connect, mikrotik_creds
):
    """Mirrors a real TrapError (e.g. DNS resolution failure) -- never
    fabricates a result when the device itself reports failure."""
    from librouteros.exceptions import TrapError

    _patch_uuid(monkeypatch)
    api = FakeRouterOSApi(
        raise_on_command={"/tool/fetch": TrapError("failure: resolving error")}
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().run_speed_test(mikrotik_creds, download_url=_TEST_URL)
    assert api.closed is True


@pytest.mark.asyncio
async def test_run_speed_test_raises_if_status_never_reaches_finished(
    monkeypatch, patch_connect, mikrotik_creds
):
    _patch_uuid(monkeypatch)
    api = FakeRouterOSApi(
        command_replies={
            "/tool/fetch": [
                {"status": "connecting"},
                {"status": "downloading", "downloaded": "100", "total": "9765", "duration": "1s"},
            ],
        },
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().run_speed_test(mikrotik_creds, download_url=_TEST_URL)


@pytest.mark.asyncio
async def test_run_speed_test_raises_rather_than_divide_by_zero_duration(
    monkeypatch, patch_connect, mikrotik_creds
):
    """A hypothetical ``duration: '0s'`` on a finished fetch must never
    silently produce an infinite/fabricated Mbps figure."""
    _patch_uuid(monkeypatch)
    api = FakeRouterOSApi(
        command_replies={
            "/tool/fetch": [
                {"status": "finished", "downloaded": "50", "total": "50", "duration": "0s"},
            ],
        },
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().run_speed_test(mikrotik_creds, download_url=_TEST_URL)


@pytest.mark.asyncio
async def test_run_speed_test_raises_if_no_bytes_downloaded(
    monkeypatch, patch_connect, mikrotik_creds
):
    _patch_uuid(monkeypatch)
    api = FakeRouterOSApi(
        command_replies={
            "/tool/fetch": [
                {"status": "finished", "downloaded": "0", "total": "0", "duration": "1s"},
            ],
        },
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().run_speed_test(mikrotik_creds, download_url=_TEST_URL)


def test_run_speed_test_reports_true_capability():
    assert MikroTikAdapter().capabilities()["run_speed_test"] is True

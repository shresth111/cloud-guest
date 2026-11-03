"""Network-wide total speed on an Instant On guest network: off by flag, previews
by default, applied only on read-back. Every request goes to the in-memory
``FakeSite``; nothing here can reach Instant On."""

from __future__ import annotations

import json

import pytest

from app.core.config import Settings
from app.domains.network_integration import instant_on_control as control
from tests.unit.test_instant_on_cloud_control import (  # noqa: F401 -- fixture
    NET,
    _settings,
    wired,
)


def _on(**overrides: object) -> Settings:
    return _settings(instant_on_network_total_write_enabled=True, **overrides)


async def _total(target, *, down=50, up=20, dry_run=False, settings=None):  # noqa: ANN001, ANN002, ANN003, ANN202
    return await control.set_venue_network_total(
        None,
        organization_id=target.organization_id,
        location_id=target.location_id,
        network_id=NET,
        download_mbps=down,
        upload_mbps=up,
        dry_run=dry_run,
        settings=settings or _on(),
    )


def test_the_flag_is_off_by_default() -> None:
    assert Settings().instant_on_network_total_write_enabled is False


async def test_flag_off_sends_nothing_even_with_cloud_control_on(wired) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    result = await _total(target, settings=_settings())
    assert result.status == "unavailable"
    assert result.reason == "network_total_not_enabled"
    assert site.requests == []


async def test_a_closed_cloud_control_gate_sends_nothing(wired) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    result = await control.set_venue_network_total(
        None,
        organization_id=None,
        location_id=target.location_id,
        network_id=NET,
        download_mbps=50,
        upload_mbps=20,
        dry_run=False,
        settings=_on(),
    )
    assert result.status == "unavailable"
    assert result.reason == "cloud_control_not_enabled"
    assert site.requests == []


async def test_preview_is_the_default_and_writes_nothing(wired) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    result = await control.set_venue_network_total(
        None,
        organization_id=target.organization_id,
        location_id=target.location_id,
        network_id=NET,
        download_mbps=50,
        upload_mbps=20,
        settings=_on(),
    )
    assert result.status == "preview"
    assert result.preview is not None
    assert (result.preview.download_mbps, result.preview.upload_mbps) == (50, 20)
    assert site.writes() == []


async def test_applies_and_reads_back_keeping_the_secret(wired) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    result = await _total(target)
    assert result.status == "applied"
    assert result.applied is not None
    assert result.applied.other_mode_limit is True
    assert (
        result.applied.network_download_mbps,
        result.applied.network_upload_mbps,
    ) == (
        50,
        20,
    )
    (put,) = site.writes()
    body = json.loads(put.content)
    assert body["preSharedKey"] == "do-not-lose-me"
    assert body["qos"]["bandwidthLimitMode"] == "perNetwork"
    assert body["qos"]["perNetworkDownstreamBandwidthLimitInMbps"] == 50
    assert body["qos"]["perNetworkUpstreamBandwidthLimitInMbps"] == 20
    assert "do-not-lose-me" not in repr(result)


async def test_preview_says_it_replaces_a_per_device_cap(wired) -> None:  # noqa: ANN001, F811
    _, _, _, target = wired
    await control.set_venue_guest_speed(
        None,
        organization_id=target.organization_id,
        location_id=target.location_id,
        network_id=NET,
        download_mbps=20,
        upload_mbps=20,
        settings=_settings(),
    )
    result = await _total(target, dry_run=True)
    assert result.preview is not None and result.preview.replaces_per_device is True


async def test_a_write_instant_on_did_not_keep_is_failed(wired) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    site.ignore_writes = True
    result = await _total(target)
    assert result.status == "failed"
    assert result.reason == "write_not_confirmed"


async def test_clearing_lets_a_per_device_cap_be_set_again(wired) -> None:  # noqa: ANN001, F811
    _, _, _, target = wired
    await _total(target)
    cleared = await _total(target, down=None, up=None)
    assert cleared.status == "applied"
    assert cleared.applied is not None and cleared.applied.other_mode_limit is False
    again = await control.set_venue_guest_speed(
        None,
        organization_id=target.organization_id,
        location_id=target.location_id,
        network_id=NET,
        download_mbps=20,
        upload_mbps=None,
        settings=_settings(),
    )
    assert again.status == "applied"


async def test_a_network_not_on_the_site_is_never_written(wired) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    result = await control.set_venue_network_total(
        None,
        organization_id=target.organization_id,
        location_id=target.location_id,
        network_id="not-this-site",
        download_mbps=50,
        upload_mbps=None,
        dry_run=False,
        settings=_on(),
    )
    assert result.status == "failed"
    assert result.reason == "network_not_found"
    assert site.writes() == []


@pytest.mark.parametrize("value", [0, 1001, True])
async def test_out_of_range_is_refused_before_any_call(wired, value) -> None:  # noqa: ANN001, F811
    site, _, _, target = wired
    with pytest.raises(ValueError):
        await _total(target, down=value)
    assert site.requests == []

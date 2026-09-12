"""The router half of a RADIUS NAS registration.

Until now this had no code path at all: the gateway method that writes the
device's `/radius` row and its `/radius incoming` CoA listener had zero
callers in the application, so the only thing that could reach a router was
the combined config script over SSH -- and a port sweep from the platform
reached only 8728 on a fleet router.

These tests cover the three things that make the push honest rather than
merely present: it refuses when it cannot work, it records a failure in a
way that survives the rollback, and a failure reaches the caller as a
non-2xx rather than a 200 with an error inside it.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.domains.guest.constants import RadiusNasDevicePushStatus
from app.domains.guest.exceptions import (
    RadiusNasDeviceOperationError,
    RadiusNasMissingCredentialsError,
    RadiusNasNotSyncedError,
)

from .test_guest import make_fixture

_RADIUS_HOST = "10.20.0.1"
_TUNNEL_IP = "10.20.0.14"


class _RecordingAdapter:
    """Captures what would have been written to the router."""

    vendor = "mikrotik"

    def __init__(self, *, fails_with: Exception | None = None) -> None:
        self.calls: list[tuple[Any, Any]] = []
        self._fails_with = fails_with

    async def push_nas_client(self, credentials, *, config):  # noqa: ANN001
        self.calls.append((credentials, config))
        if self._fails_with is not None:
            raise self._fails_with


@pytest.fixture
def radius_fixture():
    return make_fixture()


@pytest.fixture
def adapter(monkeypatch):
    recorder = _RecordingAdapter()
    monkeypatch.setattr(
        "app.domains.guest.service.get_radius_nas_adapter",
        lambda vendor: recorder,
    )
    return recorder


async def _registered_nas(fx: Any) -> Any:
    result = await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier=f"nas-{uuid.uuid4().hex[:8]}",
        shared_secret="a-shared-secret",
    )
    nas = result.nas_client
    # Column defaults are applied at INSERT; the in-memory repository these
    # suites share never flushes. Same fake-fidelity gap the deregistration
    # suite documents for ``vendor``.
    nas.device_push_status = RadiusNasDevicePushStatus.PENDING.value
    nas.device_push_error = None
    nas.device_pushed_at = None
    nas.vendor = "MikroTik"
    # A router the push can actually reach. Set here rather than in the
    # shared fake: "this router has no credentials" is a case one of these
    # tests deliberately exercises.
    fx.router.management_ip_address = "10.20.0.14"
    fx.router.api_username = "cloudguest"
    fx.router.api_credentials_encrypted = "encrypted"
    return nas


@pytest.mark.asyncio
async def test_a_successful_push_sends_the_tunnel_address_as_src_address(
    radius_fixture, adapter
):
    """The hub matches a client{} stanza by source address, so a push
    without it registers a client that can never authenticate."""
    fx = radius_fixture
    nas = await _registered_nas(fx)
    nas.ip_address = _TUNNEL_IP

    updated = await fx.radius_service.push_nas_client_to_device(
        nas_id=nas.id, radius_server_host=_RADIUS_HOST
    )

    assert len(adapter.calls) == 1
    _, config = adapter.calls[0]
    assert config.src_address == _TUNNEL_IP
    assert config.radius_server_host == _RADIUS_HOST
    assert updated.device_push_status == RadiusNasDevicePushStatus.ACTIVE.value
    assert updated.device_push_error is None
    assert updated.device_pushed_at is not None


@pytest.mark.asyncio
async def test_a_nas_the_hub_has_not_confirmed_is_refused_before_any_write(
    radius_fixture, adapter
):
    """No tunnel address means no `src-address`. Pushing anyway would put a
    registration on the router that looks right and never authenticates."""
    fx = radius_fixture
    nas = await _registered_nas(fx)
    nas.ip_address = None

    with pytest.raises(RadiusNasNotSyncedError):
        await fx.radius_service.push_nas_client_to_device(
            nas_id=nas.id, radius_server_host=_RADIUS_HOST
        )

    assert adapter.calls == []
    assert nas.device_push_status == RadiusNasDevicePushStatus.PENDING.value


@pytest.mark.asyncio
async def test_a_router_with_no_credentials_is_refused_not_reported_as_pushed(
    radius_fixture, adapter
):
    fx = radius_fixture
    nas = await _registered_nas(fx)
    nas.ip_address = _TUNNEL_IP
    fx.router.api_username = None

    with pytest.raises(RadiusNasMissingCredentialsError):
        await fx.radius_service.push_nas_client_to_device(
            nas_id=nas.id, radius_server_host=_RADIUS_HOST
        )

    assert adapter.calls == []


@pytest.mark.asyncio
async def test_a_device_failure_is_recorded_and_re_raised(
    radius_fixture, monkeypatch
):
    """`GenericRepository.update` only flushes and `get_db_session` rolls
    back on any exception, so the failure record has to be committed before
    the re-raise or it is discarded -- leaving a row that still reads as
    though the push reached the router."""
    fx = radius_fixture
    nas = await _registered_nas(fx)
    nas.ip_address = _TUNNEL_IP
    failing = _RecordingAdapter(
        fails_with=RadiusNasDeviceOperationError(
            "push_nas_client", "connection refused"
        )
    )
    monkeypatch.setattr(
        "app.domains.guest.service.get_radius_nas_adapter", lambda vendor: failing
    )

    with pytest.raises(RadiusNasDeviceOperationError):
        await fx.radius_service.push_nas_client_to_device(
            nas_id=nas.id, radius_server_host=_RADIUS_HOST
        )

    assert nas.device_push_status == RadiusNasDevicePushStatus.FAILED.value
    assert "connection refused" in nas.device_push_error
    assert nas.device_pushed_at is None


def test_a_device_failure_is_a_502_not_a_200_with_an_error_inside_it():
    """The frontend's response interceptor unwraps `data` and never reads
    `success`, so a 200 carrying an error is indistinguishable from a
    working push to every caller in the app."""
    error = RadiusNasDeviceOperationError("push_nas_client", "connection refused")
    assert error.status_code == 502


def test_refusals_are_conflicts_not_server_errors():
    """A router with no credentials, or a NAS the hub has not confirmed, is
    a state the operator can fix -- not a device fault."""
    assert RadiusNasMissingCredentialsError(uuid.uuid4()).status_code == 409
    assert RadiusNasNotSyncedError(uuid.uuid4()).status_code == 409

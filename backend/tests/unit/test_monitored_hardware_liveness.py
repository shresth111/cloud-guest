"""Unit tests for the monitored-hardware liveness sweep: the fast,
ping-driven verdict that flips a monitored device to DOWN within one tick
of it actually going offline (instead of waiting out the RouterOS DHCP
lease the discovery sync still sees as ``bound``), and back to UP when it
returns.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_isp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``run_monitored_hardware_liveness_sweep`` is exercised against
small, hand-rolled in-memory fakes for its repository (targets grouped by
router, updateable device rows) and router lookup, plus a controllable
fake adapter whose ``ping`` returns a fixed ``PingResult`` -- mirrors
``tests/unit/test_connected_devices.py``'s identical "fake the narrow
Protocol boundary" precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.domains.connected_devices.device_adapters import PingResult
from app.domains.connected_devices.exceptions import ConnectedDeviceConnectionError
from app.domains.connected_devices.models import ConnectedDevice
from app.domains.connected_devices.service import (
    run_monitored_hardware_liveness_sweep,
)
from app.domains.monitored_hardware.models import MonitoredHardware
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_router(
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


def _make_device(
    router: Router,
    *,
    mac_address: str,
    ip_address: str | None = "192.168.88.20",
    is_active: bool = True,
    connected_at: datetime | None = None,
    last_seen_at: datetime | None = None,
) -> ConnectedDevice:
    return ConnectedDevice(
        **_base_fields(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            mac_address=mac_address,
            ip_address=ip_address,
            hostname=None,
            vendor=None,
            connection_type="unknown",
            interface="bridge",
            signal_strength_dbm=None,
            is_active=is_active,
            connected_at=connected_at,
            last_seen_at=last_seen_at,
            comment=None,
            guest_id=None,
            guest_session_id=None,
        )
    )


def _make_monitored(router: Router, *, mac_address: str) -> MonitoredHardware:
    return MonitoredHardware(
        **_base_fields(
            organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            name="Hall Lobby AP",
            mac_address=mac_address,
            device_type="Access Point",
            floor=None,
        )
    )


@dataclass
class FakeLivenessRepository:
    """Fake for the sweep's repository boundary: returns whatever targets
    the test seeded and applies ``update_device`` in memory so the test
    can assert the row's resulting state."""

    targets: list[tuple[ConnectedDevice, MonitoredHardware]] = field(
        default_factory=list
    )
    update_log: list[tuple[ConnectedDevice, dict[str, object]]] = field(
        default_factory=list
    )

    async def list_monitored_targets(
        self,
    ) -> list[tuple[ConnectedDevice, MonitoredHardware]]:
        return list(self.targets)

    async def update_device(
        self, device: ConnectedDevice, data: dict[str, object]
    ) -> ConnectedDevice:
        self.update_log.append((device, dict(data)))
        for key, value in data.items():
            if hasattr(device, key):
                setattr(device, key, value)
        return device


@dataclass
class FakeLivenessRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secrets: dict[uuid.UUID, str | None] = field(default_factory=dict)

    def add(self, router: Router, *, secret: str | None = "decrypted-secret") -> Router:
        self.routers[router.id] = router
        self.secrets[router.id] = secret
        return router

    async def get_router(self, router_id: uuid.UUID, **_: object) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secrets.get(router.id)


@dataclass
class FakePingAdapter:
    vendor: str = "mikrotik"
    result: PingResult = PingResult(
        sent=2, received=2, packet_loss_percentage=0.0, avg_rtt_ms=1.5
    )
    ping_calls: list[dict[str, object]] = field(default_factory=list)
    raise_connection_error: bool = False
    #: Targets whose ping simulates an unreachable uplink router -- lets a
    #: test make one router's whole batch fail while another succeeds.
    connection_error_targets: set[str] = field(default_factory=set)

    async def ping(self, credentials, *, target: str, count: int) -> PingResult:
        self.ping_calls.append({"target": target, "count": count})
        if self.raise_connection_error or target in self.connection_error_targets:
            raise ConnectedDeviceConnectionError(credentials.host, "down in test")
        return self.result


# ============================================================================
# Liveness sweep
# ============================================================================


class TestMonitoredHardwareLivenessSweep:
    async def test_down_device_flips_inactive_without_touching_last_seen(
        self,
    ) -> None:
        """The core bug: a monitored AP that powered off must read as DOWN
        as soon as the ping stops answering -- not whenever the RouterOS
        lease finally expires. ``last_seen_at`` must keep meaning "last
        time we confirmed it alive", so a failed probe must not refresh
        it."""
        router_lookup = FakeLivenessRouterLookup()
        router = router_lookup.add(_make_router())
        original_last_seen = _now() - timedelta(minutes=1)
        device = _make_device(
            router,
            mac_address="B8:27:EB:00:00:01",
            ip_address="192.168.88.20",
            is_active=True,
            connected_at=_now() - timedelta(hours=3),
            last_seen_at=original_last_seen,
        )
        repository = FakeLivenessRepository(
            targets=[(device, _make_monitored(router, mac_address=device.mac_address))]
        )
        adapter = FakePingAdapter(
            result=PingResult(
                sent=2, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
            )
        )

        summary = await run_monitored_hardware_liveness_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        assert summary.devices_down == 1
        assert summary.devices_up == 0
        assert device.is_active is False
        assert device.last_seen_at == original_last_seen  # untouched
        assert adapter.ping_calls == [{"target": "192.168.88.20", "count": 2}]

    async def test_reachable_inactive_device_comes_up_with_connected_at_set(
        self,
    ) -> None:
        """A device the ping can reach again is UP again -- and since it
        was previously inactive, ``connected_at`` resets to now (it just
        (re)connected), matching the discovery sync's own flip semantics."""
        router_lookup = FakeLivenessRouterLookup()
        router = router_lookup.add(_make_router())
        device = _make_device(
            router,
            mac_address="B8:27:EB:00:00:02",
            ip_address="192.168.88.21",
            is_active=False,
            connected_at=None,
            last_seen_at=_now() - timedelta(hours=2),
        )
        repository = FakeLivenessRepository(
            targets=[(device, _make_monitored(router, mac_address=device.mac_address))]
        )
        adapter = FakePingAdapter()

        summary = await run_monitored_hardware_liveness_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        assert summary.devices_up == 1
        assert device.is_active is True
        assert device.connected_at is not None
        assert device.last_seen_at is not None

    async def test_already_active_device_keeps_its_connected_at(self) -> None:
        """A device that never went down keeps its original
        ``connected_at`` -- the ping sweep must not reset the "up since"
        fact every tick."""
        router_lookup = FakeLivenessRouterLookup()
        router = router_lookup.add(_make_router())
        original_connected_at = _now() - timedelta(days=2)
        device = _make_device(
            router,
            mac_address="B8:27:EB:00:00:03",
            ip_address="192.168.88.22",
            is_active=True,
            connected_at=original_connected_at,
            last_seen_at=_now() - timedelta(minutes=5),
        )
        repository = FakeLivenessRepository(
            targets=[(device, _make_monitored(router, mac_address=device.mac_address))]
        )
        adapter = FakePingAdapter()

        summary = await run_monitored_hardware_liveness_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        assert summary.devices_up == 1
        assert device.connected_at == original_connected_at

    async def test_router_connection_error_skips_whole_batch_not_false_down(
        self,
    ) -> None:
        """When the router itself is unreachable, the sweep must not write
        DOWN verdicts for the whole venue (the uplink failed, not the
        devices) -- and must keep sweeping other routers."""
        router_lookup = FakeLivenessRouterLookup()
        router_a = router_lookup.add(_make_router())
        router_b = router_lookup.add(_make_router())
        device_a = _make_device(
            router_a, mac_address="B8:27:EB:00:00:04", is_active=True
        )
        device_b = _make_device(
            router_b, mac_address="B8:27:EB:00:00:05", is_active=True
        )
        repository = FakeLivenessRepository(
            targets=[
                (device_a, _make_monitored(router_a, mac_address=device_a.mac_address)),
                (device_b, _make_monitored(router_b, mac_address=device_b.mac_address)),
            ]
        )
        adapter = FakePingAdapter(raise_connection_error=True)

        summary = await run_monitored_hardware_liveness_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        assert summary.routers_failed == 2
        assert summary.routers_probed == 0
        assert summary.devices_up == 0
        assert summary.devices_down == 0
        assert device_a.is_active is True
        assert device_b.is_active is True
        assert repository.update_log == []

    async def test_mixed_batch_isolates_router_failure(self) -> None:
        router_lookup = FakeLivenessRouterLookup()
        good = router_lookup.add(_make_router())
        bad = router_lookup.add(_make_router())
        good_device = _make_device(
            good,
            mac_address="B8:27:EB:00:00:06",
            ip_address="192.168.88.30",
            is_active=True,
        )
        bad_device = _make_device(
            bad,
            mac_address="B8:27:EB:00:00:07",
            ip_address="192.168.88.31",
            is_active=True,
        )
        repository = FakeLivenessRepository(
            targets=[
                (
                    good_device,
                    _make_monitored(good, mac_address=good_device.mac_address),
                ),
                (
                    bad_device,
                    _make_monitored(bad, mac_address=bad_device.mac_address),
                ),
            ]
        )
        adapter = FakePingAdapter(
            # The bad router's uplink is unreachable -- its ping raises a
            # connection error, exactly as a dead MikroTik would, while the
            # good router's own ping succeeds.
            result=PingResult(
                sent=2, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
            ),
            connection_error_targets={"192.168.88.31"},
        )

        summary = await run_monitored_hardware_liveness_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        # The good router's device was probed and found down; the bad
        # router's batch was skipped entirely -- no false DOWN for it.
        assert summary.routers_probed == 1
        assert summary.routers_failed == 1
        assert good_device.is_active is False
        assert bad_device.is_active is True

    async def test_device_without_ip_is_skipped_not_errored(self) -> None:
        """A registered device the discovery sync has never observed has no
        management IP to ping -- it stays in its current state (the
        monitored-hardware status derivation reports UNKNOWN for it), and
        the sweep neither pings nor writes."""
        router_lookup = FakeLivenessRouterLookup()
        router = router_lookup.add(_make_router())
        device = _make_device(
            router,
            mac_address="B8:27:EB:00:00:08",
            ip_address=None,
            is_active=False,
            connected_at=None,
            last_seen_at=None,
        )
        repository = FakeLivenessRepository(
            targets=[(device, _make_monitored(router, mac_address=device.mac_address))]
        )
        adapter = FakePingAdapter()

        summary = await run_monitored_hardware_liveness_sweep(
            repository,
            router_lookup,
            device_adapter_resolver=lambda vendor: adapter,
        )

        assert summary.skipped == 1
        assert adapter.ping_calls == []
        assert repository.update_log == []
